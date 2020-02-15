<?php
uv_getaddrinfo(uv_default_loop(),function($s,$names){
    var_dump($names);
}, "yahoo.com", NULL ,array(
    "ai_family" => UV::AF_UNSPEC
));

uv_run();
