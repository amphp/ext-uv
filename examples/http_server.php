<?php
require "http.php";
require "debug_timer.php";

createServer(function($request, $response){
    $response->writeHead(200, array("Content-Type" => "text/plain"));
    $response->write("Hello World");
    $response->end();
})->listen(8888);
