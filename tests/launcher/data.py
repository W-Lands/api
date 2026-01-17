import bcrypt

TEST_NICKNAME = "test_user1"
TEST_EMAIL = f"{TEST_NICKNAME}@example.com"
TEST_PASSWORD = "test_passw0rd)"
TEST_PASSWORD_HASH = bcrypt.hashpw(TEST_PASSWORD.encode("utf8"), bcrypt.gensalt(4)).decode("utf8")
