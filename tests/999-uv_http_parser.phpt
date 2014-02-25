--TEST--
Check for uv_http_parser
--FILE--
<?php
$parser = uv_http_parser_init();
$result = array();
if(uv_http_parser_execute($parser,"GET /img/http-parser.png?key=value#frag HTTP/1.1
Host: chobie.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:12.0) Gecko/20100101 Firefox/12.0
Accept: image/png,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://chobie.net/
Cookie: key=value
Cache-Control: max-age=0

",$result)) {
	echo "# Headers count\n";
	echo count($result['HEADERS']) . PHP_EOL;
	echo "# Headers values\n";
	echo $result['HEADERS']['HOST'] . PHP_EOL;
	echo $result['HEADERS']['USER_AGENT'] . PHP_EOL;
	echo $result['HEADERS']['ACCEPT'] . PHP_EOL;
	echo $result['HEADERS']['ACCEPT_LANGUAGE'] . PHP_EOL;
	echo $result['HEADERS']['ACCEPT_ENCODING'] . PHP_EOL;
	echo $result['HEADERS']['CONNECTION'] . PHP_EOL;
	echo $result['HEADERS']['REFERER'] . PHP_EOL;
	echo $result['HEADERS']['COOKIE'] . PHP_EOL;
	echo $result['HEADERS']['CACHE_CONTROL'] . PHP_EOL;
	echo "# other values" . PHP_EOL;
	echo $result['QUERY_STRING'] . PHP_EOL;
	echo $result['PATH'] . PHP_EOL;
	echo $result['QUERY'] . PHP_EOL;
	echo $result['FRAGMENT'] . PHP_EOL;
	echo $result['UPGRADE'] . PHP_EOL;
}

$buffer = "GET /demo HTTP/1.1
Upgrade: WebSocket
Connection: Upgrade
Host: example.com
Origin: http://example.com
WebSocket-Protocol: sample

";

$parser = uv_http_parser_init();
$result = array();
uv_http_parser_execute($parser, $buffer, $result);
var_dump($result);
--EXPECT--
# Headers count
9
# Headers values
chobie.net
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:12.0) Gecko/20100101 Firefox/12.0
image/png,image/*;q=0.8,*/*;q=0.5
en-us,en;q=0.5
gzip, deflate
keep-alive
http://chobie.net/
key=value
max-age=0
# other values
/img/http-parser.png?key=value#frag
/img/http-parser.png
key=value
frag
0
array(5) {
  ["QUERY_STRING"]=>
  string(5) "/demo"
  ["PATH"]=>
  string(5) "/demo"
  ["REQUEST_METHOD"]=>
  string(3) "GET"
  ["UPGRADE"]=>
  int(1)
  ["HEADERS"]=>
  array(5) {
    ["UPGRADE"]=>
    string(9) "WebSocket"
    ["CONNECTION"]=>
    string(7) "Upgrade"
    ["HOST"]=>
    string(11) "example.com"
    ["ORIGIN"]=>
    string(18) "http://example.com"
    ["WEBSOCKET_PROTOCOL"]=>
    string(6) "sample"
  }
}