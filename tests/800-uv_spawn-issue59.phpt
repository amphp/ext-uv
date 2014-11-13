--TEST--
Test uv_spawn doesn't cause segfault #56
--FILE--
<?php

$ioRead = uv_stdio_new(null, Uv::CREATE_PIPE | Uv::INHERIT_STREAM);

--EXPECTF--
Warning: uv_stdio_new(): passed unexpected resource in %s on line %d
