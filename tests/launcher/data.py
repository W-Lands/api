import bcrypt

TEST_NICKNAME = "test_user1"
TEST_NICKNAME2 = "test_user2"
TEST_EMAIL = f"{TEST_NICKNAME}@example.com"
TEST_EMAIL2 = f"{TEST_NICKNAME2}@example.com"
TEST_PASSWORD = "test_passw0rd)"
TEST_PASSWORD_HASH = bcrypt.hashpw(TEST_PASSWORD.encode("utf8"), bcrypt.gensalt(4)).decode("utf8")
