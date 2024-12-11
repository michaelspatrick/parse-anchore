#!/usr/bin/php -q
<?php
  $file = file("vulns.txt");

  function strip_str($haystack, $needle1, $needle2) {
    $found = "";
    $start = strpos($haystack, $needle1) + strlen($needle1);
    $end = strpos($haystack, $needle2);
    if ($end > $start) {
      $len = $end - $start;
      $found = substr($haystack, $start, $len);
    }
    return $found;
  }

  function encap($str) {
    return "\"".$str."\"";
  }

  $count = 0;
  $percona_tool = "";
  echo "\"Component\",\"Priority\",\"Software\",\"Fixed Version\",\"CVE\",\"CVE URL\",\"eBay Vuln Level\"\n";
  for ($i=0; $i < count($file); $i++) {
    $parts = explode("\t", $file[$i]);

    if (stristr($parts[0], "hub.tess.io")) {
      $pieces = explode("/", $parts[0]);
      $percona_tool = $pieces[2];
    } elseif ($parts[0] == "vulnerabilities") {
      if ((trim($parts[0]) == "vulnerabilities") && (trim($parts[3]) == "stop")) {
        $dashes = explode(" - ", trim($parts[2]));
        $par = explode("(", $dashes[1]);
        $cve = $par[3];
        $results[$count]['percona_tool'] = trim($percona_tool);
        $results[$count]['priority'] = trim(strtok($dashes[0], " "));
        $results[$count]['software'] = trim(strtok($dashes[1], " "));
        $results[$count]['fixed'] = strip_str($dashes[1], "fixed in: ", ")");
        $results[$count]['cve'] = $par[3];
        $results[$count]['cve_url'] = str_replace(")", "", trim($dashes[2]));
        $results[$count]['stop'] = trim($parts[3]);
        $count++;
      }
    }
  }

  // display CSV strings
  foreach($results as $res) $sortAux[] = $res['priority'];
  array_multisort($sortAux, SORT_ASC, $results);
  for ($i=0; $i < count($results); $i++) {
    $prev = $i - 1;
    echo encap($results[$i]['percona_tool']).",";
    echo encap($results[$i]['priority']).",";
    echo encap($results[$i]['software']).",";
    echo encap($results[$i]['fixed']).",";
    echo encap($results[$i]['cve']).",";
    echo encap($results[$i]['cve_url']).",";
    echo encap($results[$i]['stop'])."\n";
  }
?>
