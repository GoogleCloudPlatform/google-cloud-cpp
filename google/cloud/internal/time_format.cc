// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "google/cloud/internal/time_format.h"
#include <cstring>
#include <iomanip>
#include <sstream>
// GCC did not support std::get_time() or std::put_time() until version 5,
// so we fall back to using POSIX XSI strptime() and strftime() instead.
#if !defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5
#if !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE
#endif
#include <time.h>  // <ctime> doesn't have to declare strptime()
#endif

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace internal {

std::string FormatTime(char const* fmt, std::tm const& tm) {
#if !defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5
  std::string s;
  s.resize(64);
  for (;;) {
    if (auto len = strftime(&s[0], s.size(), fmt, &tm)) {
      s.resize(len);
      break;
    }
    s.resize(s.size() * 2);
  }
  return s;
#else
  std::ostringstream output;
  output << std::put_time(&tm, fmt);
  return output.str();
#endif
}

std::size_t ParseTime(char const* fmt, std::string const& s, std::tm* tm) {
#if !defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5
  char const* const bp = s.c_str();
  if (char* const ep = strptime(bp, fmt, tm)) {
    return ep - bp;
  }
  return std::string::npos;
#else
  std::istringstream input(s);
  input >> std::get_time(tm, fmt);
  if (!input) {
    return std::string::npos;
  }
  auto const pos = input.tellg();
  if (pos >= 0) {
    return pos;
  }
  return s.size();
#endif
}

namespace {

// A duration capable of holding subsecond values at high precision.
using femtoseconds = std::chrono::duration<std::int64_t, std::femto>;
using time_point = std::chrono::system_clock::time_point;

// Convert a std::time_t into a Zulu std::tm.
//
// See http://howardhinnant.github.io/date_algorithms.html for an explanation
// of the calendrical arithmetic in ZTime() and TimeZ().  For quick reference,
// March 1st is used as the first day of the year (so that any leap day occurs
// at year's end), there are 719468 days between 0000-03-01 and 1970-01-01,
// and there are 146097 days in the 400-year Gregorian cycle (an era).
std::tm ZTime(std::time_t const t) {
  std::time_t sec = t % (24 * 60 * 60);
  std::time_t day = t / (24 * 60 * 60);
  if (sec < 0) {
    sec += 24 * 60 * 60;
    day -= 1;
  }

  day += 719468;
  std::time_t const era = (day >= 0 ? day : day - 146096) / 146097;
  std::time_t const doe = day - era * 146097;
  std::time_t const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  std::time_t const y = yoe + era * 400;
  std::time_t const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  std::time_t const mp = (5 * doy + 2) / 153;
  std::time_t const d = doy - (153 * mp + 2) / 5 + 1;
  std::time_t const m = mp + (mp < 10 ? 3 : -9);

  std::tm tm;
  tm.tm_year = static_cast<int>(y + (m <= 2 ? 1 : 0) - 1900);
  tm.tm_mon = static_cast<int>(m - 1);
  tm.tm_mday = static_cast<int>(d);
  tm.tm_hour = static_cast<int>(sec / (60 * 60));
  tm.tm_min = static_cast<int>((sec / 60) % 60);
  tm.tm_sec = static_cast<int>(sec % 60);
  return tm;
}

// Convert a Zulu std::tm into a std::time_t.
std::time_t TimeZ(std::tm const& tm) {
  std::time_t const y = tm.tm_year + 1900L;
  std::time_t const m = tm.tm_mon + 1;
  std::time_t const d = tm.tm_mday;

  std::time_t const eyear = (m <= 2) ? y - 1 : y;
  std::time_t const era = (eyear >= 0 ? eyear : eyear - 399) / 400;
  std::time_t const yoe = eyear - era * 400;
  std::time_t const doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  std::time_t const doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  std::time_t const day = era * 146097 + doe - 719468;

  return (((day * 24) + tm.tm_hour) * 60 + tm.tm_min) * 60 + tm.tm_sec;
}

// Split a time_point into a Zulu std::tm and a (>=0) femto subsecond.
std::pair<std::tm, femtoseconds> SplitTime(time_point tp) {
  std::time_t t = std::chrono::system_clock::to_time_t(tp);
  time_point ttp = std::chrono::system_clock::from_time_t(t);
  auto ss = std::chrono::duration_cast<femtoseconds>(tp - ttp);
  if (ss.count() < 0) {
    t -= 1;
    ss += std::chrono::seconds(1);
  }
  return {ZTime(t), ss};
}

bool IsLeapYear(int year) {
  return (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}

StatusOr<std::pair<std::tm, std::size_t>> ParseDateTime(std::string const& s,
                                                        std::size_t pos) {
  int year, month, day;
  char date_time_separator;
  int hours, minutes, seconds;

  char const* buffer = s.data() + pos;
  int width;
  auto count =
      std::sscanf(buffer, "%4d-%2d-%2d%c%2d:%2d:%2d%n", &year, &month, &day,
                  &date_time_separator, &hours, &minutes, &seconds, &width);
  pos += width;
  // All the fields up to this point have fixed width, so total width must be:
  constexpr int kExpectedWidth = 19;
  constexpr int kExpectedFields = 7;
  if (count != kExpectedFields || pos != kExpectedWidth) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Invalid format for RFC 3339 timestamp");
  }
  if (date_time_separator != 'T' && date_time_separator != 't') {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Invalid date-time separator, expected 'T' or 't'.");
  }
  if (month < 1 || month > 12) {
    return Status(StatusCode::kInvalidArgument, s + ": Out of range month.");
  }
  constexpr int kMaxDaysInMonth[] = {
      31,  // January
      29,  // February (non-leap years checked below)
      31,  // March
      30,  // April
      31,  // May
      30,  // June
      31,  // July
      31,  // August
      30,  // September
      31,  // October
      30,  // November
      31,  // December
  };
  if (day < 1 || day > kMaxDaysInMonth[month - 1]) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Out of range day for given month.");
  }
  if (2 == month && day > 28 && !IsLeapYear(year)) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Out of range day for given month.");
  }
  if (hours < 0 || hours > 23) {
    return Status(StatusCode::kInvalidArgument, s + ": Out of range hour.");
  }
  if (minutes < 0 || minutes > 59) {
    return Status(StatusCode::kInvalidArgument, s + ": Out of range minute.");
  }
  // RFC-3339 points out that the seconds field can only assume value '60' for
  // leap seconds, so theoretically, we should validate that (furthermore, we
  // should valid that `seconds` is smaller than 59 for negative leap seconds).
  // This would require loading a table, and adds too much complexity for little
  // value.
  if (seconds < 0 || seconds > 60) {
    return Status(StatusCode::kInvalidArgument, s + ": Out of range second.");
  }

  std::tm tm{};
  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  tm.tm_hour = hours;
  tm.tm_min = minutes;
  tm.tm_sec = seconds;
  return std::make_pair(tm, pos);
}

// Parse the fractional, sub-second portion of a timestamp, starting at pos.
StatusOr<std::pair<femtoseconds, std::size_t>> ParseFractional(
    std::string const& s, std::size_t pos) {
  auto const len = s.size();
  femtoseconds ss(0);
  if (s[pos] == '.') {
    femtoseconds::rep v = 0;
    auto scale = std::femto::den;
    auto fpos = pos + 1;  // start of fractional part
    while (++pos != len) {
      static constexpr auto kDigits = "0123456789";
      char const* dp = std::strchr(kDigits, s[pos]);
      if (dp == nullptr || *dp == '\0') {
        break;  // non-digit
      }
      if (scale == 1) {
        continue;  // drop insignificant digits
      }
      scale /= 10;
      v *= 10;
      v += dp - kDigits;
    }
    if (pos == fpos) {
      return Status(StatusCode::kInvalidArgument,
                    s + ": RFC3339 time-secfrac must include a digit");
    }
    ss = femtoseconds(v * scale);
  }
  return std::make_pair(ss, pos);
}

StatusOr<std::pair<std::chrono::seconds, std::size_t>> ParseOffset(
    std::string const& s, std::size_t pos) {
  char const* buffer = s.data() + pos;
  if (buffer[0] == '+' || buffer[0] == '-') {
    bool positive = (buffer[0] == '+');
    ++buffer;
    // Parse the HH:MM offset.
    int hours, minutes, width;
    auto count = std::sscanf(buffer, "%2d:%2d%n", &hours, &minutes, &width);
    constexpr int kExpectedOffsetWidth = 5;
    constexpr int kExpectedOffsetFields = 2;
    if (count != kExpectedOffsetFields || width != kExpectedOffsetWidth) {
      return Status(
          StatusCode::kInvalidArgument,
          s + ": RFC3339 timezone offset must be in [+-]HH:MM format");
    }
    if (hours < 0 || hours > 23) {
      return Status(StatusCode::kInvalidArgument,
                    s + ": RFC3339 timezone offset hours must be in [0,24)"
                        " range");
    }
    if (minutes < 0 || minutes > 59) {
      return Status(StatusCode::kInvalidArgument,
                    s + ": RFC3339 timezone offset minutes must be in [0,60)"
                        " range");
    }
    pos += width + 1;
    auto offset = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::hours(hours) + std::chrono::minutes(minutes));
    if (positive) {
      return make_pair(offset, pos);
    }
    return make_pair(-offset, pos);
  }
  if (buffer[0] != 'Z' && buffer[0] != 'z') {
    return Status(
        StatusCode::kInvalidArgument,
        s + ": Invalid RFC3339 timezone offset, expected 'Z' or 'z'.");
  }
  pos++;
  return std::make_pair(std::chrono::seconds(0), pos);
}

// Combine a Zulu std::tm and a femto subsecond into a time_point.
time_point CombineTime(std::tm const& tm, femtoseconds ss) {
  using namespace std::chrono;
  auto sub = duration_cast<system_clock::duration>(ss);
  return system_clock::from_time_t(TimeZ(tm)) + sub;
}

// RFC3339 "date-time" prefix (no "time-secfrac" or "time-offset").
constexpr auto kTimeFormat = "%Y-%m-%dT%H:%M:%S";

}  // namespace

std::string TimestampToString(time_point tp) {
  std::ostringstream output;
  auto bd = SplitTime(tp);
  output << FormatTime(kTimeFormat, bd.first);
  if (auto ss = bd.second.count()) {  // femtoseconds
    int width = 15;                   // log10(std::femto::den)
    while (ss % 10 == 0) {
      ss /= 10;
      width -= 1;
    }
    output << '.' << std::setfill('0') << std::setw(width) << ss;
  }
  output << 'Z';
  return output.str();
}

StatusOr<time_point> TimestampFromStringZ(std::string const& s) {
  auto const len = s.size();
  auto tm = ParseDateTime(s, 0);
  if (!tm) {
    return tm.status();
  }
  auto pos = tm->second;
  if (pos == std::string::npos || pos == len) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Failed to match RFC3339 date-time");
  }

  auto ss = ParseFractional(s, pos);
  if (!ss) {
    return ss.status();
  }

  pos = ss->second;
  if (pos == len || s[pos] != 'Z') {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Missing RFC3339 time-offset 'Z'");
  }
  if (++pos != len) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Extra data after RFC3339 date-time");
  }

  return CombineTime(tm->first, ss->first);
}

StatusOr<time_point> TimestampFromString(std::string const& s) {
  auto const len = s.size();
  auto tm = ParseDateTime(s, 0);
  if (!tm) {
    return tm.status();
  }
  auto pos = tm->second;
  if (pos == std::string::npos || pos == len) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Failed to match RFC3339 date-time");
  }

  auto ss = ParseFractional(s, pos);
  if (!ss) {
    return ss.status();
  }

  pos = ss->second;
  auto offset = ParseOffset(s, pos);
  if (!offset) {
    return offset.status();
  }
  pos = offset->second;
  if (pos != len) {
    return Status(StatusCode::kInvalidArgument,
                  s + ": Extra data after RFC3339 date-time");
  }

  auto tp = CombineTime(tm->first, ss->first);
  tp -= offset->first;
  return tp;
}

}  // namespace internal
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google
