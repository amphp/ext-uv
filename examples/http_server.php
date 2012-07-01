<?php
/* do we need these function ? */
ob_implicit_flush(true);
ob_end_flush();


global $servers;

$servers = 0;
$timer = uv_timer_init();
$stat = array();
$stat['begin'] = memory_get_usage();

uv_timer_start($timer, 10, 1000, function($stat, $timer) use (&$stat){
    global $servers;
    $stat["current"] = memory_get_usage();
    printf("memory: %d\n", $stat["current"] - $stat['begin']);
    printf("servers: %d\n", $servers);
});


$server = uv_tcp_init();
uv_tcp_bind6($server,uv_ip6_addr("::1",8888));
uv_tcp_nodelay($server, 1);

function on_connect($server)
{
    global $servers;
    global $parsers;

    echo "[LISTEN]" . PHP_EOL;
    $client = uv_tcp_init();
    uv_tcp_nodelay($client, 1);
    uv_accept($server,$client);
    $servers++;
    echo "-Error: " . uv_err_name(uv_last_error(uv_default_loop())) . PHP_EOL;

    echo "[Accept]" . PHP_EOL;
    $parsers[(int)($client)] = uv_http_parser_init();

    uv_read_start($client, "on_read");
}


function on_read($client, $buffer, $nread)
{
        //echo $buffer;
        echo "--Error: " . uv_err_name(uv_last_error(uv_default_loop())) . PHP_EOL;
        
        global $parsers;
        if ($nread < 0) {
           echo "[NREAD={$nread}]\n";
           uv_shutdown($client, "on_shutdown");
        } else if ($nread == 0) {
            // nothing to do.
           echo "[NREAD=0]\n";
        } else {
            $result = array();
            echo "parser" . PHP_EOL;
            if (uv_http_parser_execute($parsers[(int)($client)], $buffer, $result)){
                echo $buffer;
                echo PHP_EOL;
                $response = "HTTP/1.0 200 OK
Pragma: no-cache
Accept-Ranges: bytes
Content-Length: 6
Connection: close
Content-Type: text/html

Hello
";
                echo $response;
                uv_write($client,$response,"on_write");
            } else {
                // nothing todo. (waiting next buffer)
            }
        }    
}

function on_shutdown($handle)
{
    global $parsers;
    global $servers;
    $servers--;
    unset($parsers[(int)$handle]);
    echo "shutdown" . PHP_EOL;

    uv_close($handle, function($handle){
        echo "=close\n";
    });
}

function on_shutdown2($handle)
{
    uv_close($handle,function($handle){echo "==close\n";});
}

function on_write($status, $client)
{
    global $servers;
    global $parsers;
    $servers--;

    unset($parsers[(int)$client]);
    if ($status == 0) {
        uv_shutdown($client, "on_shutdown2");
    } else {
        echo "[write_failed]";
    }    
}


uv_listen($server, 127, "on_connect");
uv_run();