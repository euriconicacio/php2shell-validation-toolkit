<?php
// Ordinary allocation. No attack payload. Shows what PHP does when a request
// crosses memory_limit mid-execution: pre-fix branches bail out (fatal E_ERROR
// via longjmp); the fixed engine raises a delayed OOM at a safe point.
ini_set('memory_limit', '16M');
register_shutdown_function(function () {
    $e = error_get_last();
    echo "SHUTDOWN ran. last_error=", $e ? $e['message'] : 'none', "\n";
});
$a = array();
for ($i = 0; $i < 100000000; $i++) { $a[] = str_repeat('x', 1024); }
echo "completed without hitting the limit\n";
