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
	echo count($result['headers']) . PHP_EOL;
	echo "# Headers values\n";
	echo $result['headers']['Host'] . PHP_EOL;
	echo $result['headers']['User-Agent'] . PHP_EOL;
	echo $result['headers']['Accept'] . PHP_EOL;
	echo $result['headers']['Accept-Language'] . PHP_EOL;
	echo $result['headers']['Accept-Encoding'] . PHP_EOL;
	echo $result['headers']['Connection'] . PHP_EOL;
	echo $result['headers']['Referer'] . PHP_EOL;
	echo $result['headers']['Cookie'] . PHP_EOL;
	echo $result['headers']['Cache-Control'] . PHP_EOL;
	echo "# other values" . PHP_EOL;
	echo $result['QUERY_STRING'] . PHP_EOL;
	echo $result['path'] . PHP_EOL;
	echo $result['query'] . PHP_EOL;
	echo $result['fragment'] . PHP_EOL;
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
