<?php
$tcp = uv_tcp_init();

uv_tcp_bind($tcp, uv_ip4_addr('0.0.0.0',79));
$users = array(
    array(
        "username" => "chobie",
        "name"     => "Shuhei Tanuma",
        "twitter"  => "chobi_e",
    ),
);

function pad($str)
{
    return str_pad($str, 20, ' ',STR_PAD_RIGHT);
}

uv_listen($tcp, 100, function($server) use ($users) {
    $client = uv_tcp_init();
    uv_accept($server, $client);
    uv_read_start($client, function($socket, $buffer) use ($users){
        $buffer = str_replace("/W","",$buffer);
        if ($buffer == "\r\n") {
            $data = "";
            $keys = array("Login","Name","Twitter");
            $data .= join("",array_map("pad",$keys)) . "\r\n";
            foreach($users as $user) {
                $data .= join("", array_map("pad",array_values($user))) . "\r\n";
            }

            uv_write($socket, $data, function($client, $stat) {
                uv_close($client);
            });
        } else {
            var_dump($buffer);
            uv_close($socket);
        }
    });
});

uv_run();
