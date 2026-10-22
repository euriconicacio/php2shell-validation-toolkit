<?php
// Receives the POST and reports how many bytes PHP parsed. If parsing OOMs,
// this script never runs and the worker faults instead.
echo "PARSED ", PHP_VERSION, " fields=", count($_POST), " files=", count($_FILES),
     " peak=", round(memory_get_peak_usage(1)/1048576,1), "M\n";
