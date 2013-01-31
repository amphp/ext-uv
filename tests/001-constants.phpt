--TEST--
Check for php-uv constants
--FILE--
<?php

if (!defined("UV::CHANGE")) {
  echo "FAILED UV::CHANGE" . PHP_EOL;
}
if (!defined("UV::RENAME")) {
  echo "FAILED UV::RENAME" . PHP_EOL;
}
if (!defined("UV::O_RDONLY")) {
  echo "FAILED UV::O_RDONLY" . PHP_EOL;
}
if (!defined("UV::O_WRONLY")) {
  echo "FAILED UV::O_WRONLY" . PHP_EOL;
}
if (!defined("UV::O_RDWR")) {
  echo "FAILED UV::O_RDWR" . PHP_EOL;
}
if (!defined("UV::O_CREAT")) {
  echo "FAILED UV::O_CREAT" . PHP_EOL;
}
if (!defined("UV::O_EXCL")) {
  echo "FAILED UV::O_EXCL" . PHP_EOL;
}
if (!defined("UV::O_TRUNC")) {
  echo "FAILED UV::O_TRUNC" . PHP_EOL;
}
if (!defined("UV::O_APPEND")) {
  echo "FAILED UV::O_APPEND" . PHP_EOL;
}
if (!defined("UV::O_NOCTTY")) {
  echo "FAILED UV::O_NOCTTY" . PHP_EOL;
}
if (!defined("UV::S_IRWXU")) {
  echo "FAILED UV::S_IRWXU" . PHP_EOL;
}
if (!defined("UV::S_IRUSR")) {
  echo "FAILED UV::S_IRUSR" . PHP_EOL;
}
if (!defined("UV::S_IWUSR")) {
  echo "FAILED UV::S_IWUSR" . PHP_EOL;
}
if (!defined("UV::S_IXUSR")) {
  echo "FAILED UV::S_IXUSR" . PHP_EOL;
}
if (!defined("UV::S_IRWXG")) {
  echo "FAILED UV::S_IRWXG" . PHP_EOL;
}
if (!defined("UV::S_IRGRP")) {
  echo "FAILED UV::S_IRGRP" . PHP_EOL;
}
if (!defined("UV::S_IWGRP")) {
  echo "FAILED UV::S_IWGRP" . PHP_EOL;
}
if (!defined("UV::S_IXGRP")) {
  echo "FAILED UV::S_IXGRP" . PHP_EOL;
}
if (!defined("UV::S_IRWXO")) {
  echo "FAILED UV::S_IRWXO" . PHP_EOL;
}
if (!defined("UV::S_IROTH")) {
  echo "FAILED UV::S_IROTH" . PHP_EOL;
}
if (!defined("UV::S_IWOTH")) {
  echo "FAILED UV::S_IWOTH" . PHP_EOL;
}
if (!defined("UV::S_IXOTH")) {
  echo "FAILED UV::S_IXOTH" . PHP_EOL;
}
if (!defined("UV::AF_INET")) {
  echo "FAILED UV::AF_INET" . PHP_EOL;
}
if (!defined("UV::AF_INET6")) {
  echo "FAILED UV::AF_INET6" . PHP_EOL;
}
if (!defined("UV::AF_UNSPEC")) {
  echo "FAILED UV::AF_UNSPEC" . PHP_EOL;
}
if (!defined("UV::LEAVE_GROUP")) {
  echo "FAILED UV::LEAVE_GROUP" . PHP_EOL;
}
if (!defined("UV::JOIN_GROUP")) {
  echo "FAILED UV::JOIN_GROUP" . PHP_EOL;
}


--EXPECT--
