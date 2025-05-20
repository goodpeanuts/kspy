<?php
if ($_FILES['file']) {
    $upload_dir = './uploads/';
    $filename = $_FILES['file']['name'];
    $filepath = $upload_dir . $filename;

    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0700, true);
    }

    if (move_uploaded_file($_FILES['file']['tmp_name'], $filepath)) {
        echo "File uploaded: <a href='uploads/$filename'>$filename</a>";
    } else {
        echo "Upload failed.";
    }
}
?>

<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
