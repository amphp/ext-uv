--TEST--
Check for uv_hrtime
--FILE--
<?php
/* is this correct ?*/
$hrtime = uv_hrtime();

--EXPECT--
