<?php


uv_fs_event_init(uv_default_loop(),"/tmp/",function($rsc,$name,$event,$stat){
    var_dump($name);

    var_dump($event);
},0);

uv_run();
