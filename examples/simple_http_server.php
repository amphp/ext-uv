<?php
require "debug_timer.php";

$address = "::1";
$port = 8888;


$banner = <<<EOF
#    # ##### ##### #####         ##### ##### #####  #     # ##### #####
#    #   #     #   #    #       #      #     #    # #     # #     #    #
######   #     #   #    # ##### #####  ##### #####   #   #  ##### #####
#    #   #     #   #####             # #     #  #    #   #  #     #  #
#    #   #     #   #            #    # #     #   ##   # #   #     #   ##
#    #   #     #   #            #####  ##### #    #    #    ##### #    #

http server started on port $port

EOF;

echo $banner;

$server = uv_tcp_init();
uv_tcp_bind6($server, uv_ip6_addr($address, $port));

$clients = array();
$parsers = array();

uv_listen($server, 511, function($server_stream) use (&$parsers, &$clients){
    $client = uv_tcp_init();
    uv_accept($server_stream, $client);

    $clients[(int)$client] = $client;
    $parsers[(int)$client] = uv_http_parser_init();

    uv_read_start($client, function($client, $nread, $buffer) use (&$parsers, &$clients){
        if ($nread < 0) {
            uv_shutdown($client, function($client) use (&$parsers, &$clients){
                uv_close($client, function($client) use (&$parsers, &$clients){
                        unset($parsers[(int)$client]);
                        unset($clients[(int)$client]);
                });
            });
            return;
        } else if ($nread == 0) {
            if (uv_last_error() == UV::EOF) {
                uv_shutdown($client, function($client) use (&$parsers, &$clients){
                    uv_close($client, function($client) use (&$parsers, &$clients){
                        unset($parsers[(int)$client]);
                        unset($clients[(int)$client]);
                    });
                });
                return;
            }
        } else {
            $result = array();
            if (uv_http_parser_execute($parsers[(int)$client], $buffer, $result)){
                $response = "HTTP/1.1 200 OK\r\n\r\nHello World";

                uv_write($client, $response, function($client) use (&$parsers, &$clients){
                    uv_close($client, function($client) use (&$parsers, &$clients){
                        unset($parsers[(int)$client]);
                        unset($clients[(int)$client]);
                    });
                });
            }
        }
    });
});

uv_run(uv_default_loop());
