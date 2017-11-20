<?php
$idkelas=$_GET['idk'];
$show_kelas1="SELECT * FROM kelas WHERE id_kelas='$idkelas'";
$hasil_kelas=mysql_query($show_kelas,$koneksi);
?>