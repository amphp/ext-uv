--TEST--
Check for uv_cwd
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
}
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
