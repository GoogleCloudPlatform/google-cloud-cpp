#include "../../firestore/google/firestore/field_path.h"
#include <gtest/gtest.h>

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

TEST(FieldPath, EmptyStringInPart) {
  const std::vector<std::string> parts = {"a", "", "b"};
  ASSERT_THROW(auto path = firestore::FieldPath(parts), std::invalid_argument);
}

TEST(FieldPath, InvalidCharsInConstructor) {
  const std::vector<std::string> parts = {"~*/[]"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`~*/[]`");
}

TEST(FieldPath, Component) {
  const std::vector<std::string> parts = {"a..b"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`a..b`");
}

TEST(FieldPath, Unicode) {
  const std::vector<std::string> parts = {"一", "二", "三"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`一`.`二`.`三`");
}

TEST(FieldPath, InvalidChar1) {
  ASSERT_THROW(auto path = firestore::FieldPath::from_string("~"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidChar2) {
  ASSERT_THROW(auto path = firestore::FieldPath::from_string("*"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidChar3) {
  ASSERT_THROW(auto path = firestore::FieldPath::from_string("/"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidChar4) {
  ASSERT_THROW(auto path = firestore::FieldPath::from_string("["),
               std::invalid_argument);
}

TEST(FieldPath, InvalidChar5) {
  ASSERT_THROW(auto path = firestore::FieldPath::from_string("]"),
               std::invalid_argument);
}

TEST(FieldPath, ToApiReprA) {
  const std::vector<std::string> parts = {"a"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "a");
}

TEST(FieldPath, ToApiReprBacktick) {
  const std::vector<std::string> parts = {"`"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`\\``");
}

TEST(FieldPath, ToApiReprDot) {
  const std::vector<std::string> parts = {"."};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`.`");
}

TEST(FieldPath, ToApiReprSlash) {
  const std::vector<std::string> parts = {"\\"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`\\\\`");
}

TEST(FieldPath, ToApiReprDoubleSlash) {
  const std::vector<std::string> parts = {"\\\\"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`\\\\\\\\`");
}

TEST(FieldPath, ToApiReprUnderscore) {
  const std::vector<std::string> parts = {"_33132"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "_33132");
}

TEST(FieldPath, ToApiReprUnicodeNonSimple) {
  const std::vector<std::string> parts = {"一"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`一`");
}

TEST(FieldPath, ToApiReprNumberNonSimple) {
  const std::vector<std::string> parts = {"03"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`03`");
}

TEST(FieldPath, ToApiReprSimpleWithDot) {
  const std::vector<std::string> parts = {"a.b"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`a.b`");
}

TEST(FieldPath, ToApiReprNonSimpleWithDot) {
  const std::vector<std::string> parts = {"a.一"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "`a.一`");
}

TEST(FieldPath, ToApiReprSimple) {
  const std::vector<std::string> parts = {"a0332432"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(), "a0332432");
}

TEST(FieldPath, ToApiReprChain) {
  const std::vector<std::string> parts = {"a",   "`",    "\\",       "_3", "03",
                                          "a03", "\\\\", "a0332432", "一"};
  auto path = firestore::FieldPath(parts);
  ASSERT_EQ(path.to_api_repr(),
            "a.`\\``.`\\\\`._3.`03`.a03.`\\\\\\\\`.a0332432.`一`");
}

TEST(FieldPath, FromString) {
  auto field_path = firestore::FieldPath::from_string("a.b.c");
  ASSERT_EQ(field_path.to_api_repr(), "a.b.c");
}

TEST(FieldPath, FromStringNonSimple) {
  auto field_path = firestore::FieldPath::from_string("a.一");
  ASSERT_EQ(field_path.to_api_repr(), "a.`一`");
}

TEST(FieldPath, InvalidCharsFromString1) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("~"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidCharsFromString2) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("*"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidCharsFromString3) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("/"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidCharsFromString4) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("["),
               std::invalid_argument);
}

TEST(FieldPath, InvalidCharsFromString5) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("]"),
               std::invalid_argument);
}

TEST(FieldPath, InvalidCharsFromString6) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("."),
               std::invalid_argument);
}

TEST(FieldPath, FromStringEmptyFieldName) {
  ASSERT_THROW(auto field_path = firestore::FieldPath::from_string("a..b"),
               std::invalid_argument);
}

TEST(FieldPath, Key) {
  std::vector<std::string> parts = {"a321", "b456"};
  auto field_path = firestore::FieldPath(parts);
  auto field_path_same = firestore::FieldPath::from_string("a321.b456");
  std::vector<std::string> string = {"a321.b456"};
  auto field_path_different = firestore::FieldPath(string);
  ASSERT_EQ(field_path, field_path_same);
  ASSERT_NE(field_path, field_path_different);
}

TEST(FieldPath, append) {
  std::vector<std::string> parts = {"a321", "b456"};
  auto field_path = firestore::FieldPath(parts);
  auto field_path_string = "c789.d";
  std::vector<std::string> parts_2 = {"c789", "d"};
  auto field_path_class = firestore::FieldPath(parts_2);
  auto string = field_path.append(field_path_string);
  auto klass = field_path.append(field_path_class);
  ASSERT_EQ(string.to_api_repr(), "a321.b456.c789.d");
  ASSERT_EQ(klass.to_api_repr(), string.to_api_repr());
}
