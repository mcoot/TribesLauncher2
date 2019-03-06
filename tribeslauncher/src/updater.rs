use std::cmp;

use std::collections::BTreeMap;
use std::io;
use std::fs;
use std::path;

use treexml;
use treexml::Document;

use reqwest;

use fs_extra;

#[derive(Debug)]
pub enum Error {
    FileError(&'static str),
    NetworkError(&'static str),
    VersionManifestError(&'static str),
}

impl From<treexml::Error> for Error {
    fn from(_e: treexml::Error) -> Error {
        Error::VersionManifestError("error parsing XML")
    }
}

fn read_version_xml(filename: &str) -> Result<BTreeMap<String, f64>, Error> {
    let file_contents = fs::read_to_string(filename).or(Err(Error::FileError("failed to read manifest file")))?;

    let doc = Document::parse(file_contents.as_bytes())?;
    let root = doc.root.ok_or(Error::VersionManifestError("missing root element"))?;

    let files = root.find_child(|tag| tag.name == "files").ok_or(Error::VersionManifestError("missing files definition"))?;

    // Validate children
    if files.children.iter().any(|tag| tag.name != "file" 
                                       || !tag.attributes.contains_key("version")
                                       || tag.attributes.get("version").unwrap().parse::<f64>().is_err()
                                       || tag.text.is_none()) {
                                       
        return Err(Error::VersionManifestError("invalid file definition"));
    }

   Ok( files.children.iter()
    .map(|tag| (tag.text.clone().unwrap(), tag.attributes.get("version").unwrap().parse::<f64>().unwrap()) )
    .collect())
}

fn download_file(remote_url: &str, dest_filename: &str) -> Result<(), Error> {
    let mut resp = reqwest::get(remote_url).or(Err(Error::NetworkError("failed to get remote version manifest")))?;
    let mut out = fs::File::create(dest_filename).or(Err(Error::FileError("failed to save remote version manifest")))?;
    io::copy(&mut resp, &mut out).or(Err(Error::FileError("failed to save remote version manifest")))?;

    Ok(())
}

enum UpdateOperationType {
    Download,
    Delete,
}

struct UpdateOperation {
    filename: String,
    operation: UpdateOperationType
}

impl UpdateOperation {
    fn new(filename: String, operation: UpdateOperationType) -> UpdateOperation {
        UpdateOperation { filename, operation }
    }
}

/// Find the files that need to be updated or deleted
/// Both maps are BTreeMaps, so they are sorted
fn diff_manifests(remote: &BTreeMap<String, f64>, local: &BTreeMap<String, f64>) -> Vec<UpdateOperation> {
    let mut result = Vec::new();

    let mut remote_iter = remote.iter();
    let mut local_iter = local.iter();
    let mut remote_cur = remote_iter.next();
    let mut local_cur = local_iter.next();
    loop {
        match remote_cur {
            Some((remote_file, remote_version)) => {
                match local_cur {
                    Some((local_file, local_version)) => {
                        match remote_file.cmp(local_file) {
                            cmp::Ordering::Less => {
                                // Remote < local
                                // Therefore current remote file does not exist in local, should be downloaded
                                result.push(UpdateOperation::new(remote_file.clone(), UpdateOperationType::Download));
                                remote_cur = remote_iter.next();
                            }
                            cmp::Ordering::Equal => {
                                // Remote == local
                                if remote_version > local_version {
                                    // Updated file, mark for download
                                    result.push(UpdateOperation::new(remote_file.clone(), UpdateOperationType::Download));
                                }
                                remote_cur = remote_iter.next();
                                local_cur = local_iter.next();
                            }
                            cmp::Ordering::Greater => {
                                // Remote > local
                                // Therefore current local file does not exist in remote, should be deleted
                                result.push(UpdateOperation::new(local_file.clone(), UpdateOperationType::Delete));
                                local_cur = local_iter.next();
                            }
                        }
                    }
                    None => {
                        // Out of local items, the rest of the remote items need to be marked for download
                        result.push(UpdateOperation::new(remote_file.clone(), UpdateOperationType::Download));
                        for (remote_file, _) in remote_iter {
                            result.push(UpdateOperation::new(remote_file.clone(), UpdateOperationType::Download));
                        }
                        break
                    }
                }
            }
            None => {
                // Out of remote items, the rest of the local items need to be marked for deletion
                if let Some((local_file, _)) = local_cur {
                    result.push(UpdateOperation::new(local_file.clone(), UpdateOperationType::Delete));
                }
                for (local_file, _) in local_iter {
                    result.push(UpdateOperation::new(local_file.clone(), UpdateOperationType::Delete));
                }
                break
            }
        }
    }

    result
}

fn find_files_needing_update(remote_url: &str, local_filename: &str, temp_directory: &str) -> Result<Vec<UpdateOperation>, Error> {
    fs::create_dir_all(temp_directory).or(Err(Error::FileError("failed to create temporary directory")))?;

    let dl_path = path::Path::new(temp_directory).join("version.xml");
    let dl_path = dl_path.to_str().ok_or(Error::FileError("failed to create manifest downlod path"))?;

    // Download the remote manifest
    download_file(remote_url, dl_path)?;

    // Get the file listings from the old and new manifests
    let remote_files = read_version_xml("./tmp/version.xml")?;
    let local_files = if !path::Path::new(local_filename).exists() {
        BTreeMap::new()
    } else {
        read_version_xml(local_filename)?
    };

    Ok(diff_manifests(&remote_files, &local_files)) 
}

fn download_update_files(remote_url_base: &str, temp_directory: &str, update_diff: Vec<UpdateOperation>) -> Result<(), Error> {
    for UpdateOperation { filename, operation } in update_diff {
        match operation {
            UpdateOperationType::Download => {
                let remote_url = format!("{}/{}", remote_url_base, filename);
                let dl_path = path::Path::new(temp_directory).join(filename);

                // Ensure appropriate directory exists
                let containing_dir = dl_path.parent().ok_or(Error::FileError("failed to get file download directory"))?;
                fs::create_dir_all(containing_dir)
                    .or(Err(Error::FileError("failed to create temporary directory")))?;

                let dl_path = dl_path.to_str().ok_or(Error::FileError("failed to create file download path"))?;
                download_file(&remote_url, dl_path)?;
            }
            UpdateOperationType::Delete => {
                // For now we ignore deletes and just leave old files
                // This may be implemented in future
            }
        }
    }

    Ok(())
}

fn copy_update_files(temp_directory: &str, main_output_directory: &str, config_output_directory: &str) -> Result<(), Error> {
    let copy_options = fs_extra::dir::CopyOptions { 
        overwrite: true, 
        skip_exist: false, 
        buffer_size: 64000, 
        copy_inside: true, 
        depth: 0
    };

    // Copy config root files, if any exist
    let config_tmp_dir = path::Path::new(temp_directory).join("!CONFIG");
    if config_tmp_dir.exists() {
        let to_copy = fs::read_dir(&config_tmp_dir).or(Err(Error::FileError("failed to iterate over downloaded files")))?;
        let to_copy = to_copy.map(|r| r.unwrap().path()).collect();
        fs_extra::copy_items(&to_copy, config_output_directory, &copy_options)
            .or(Err(Error::FileError("failed to overwrite existing config root files")))?;
        // Remove config root temp
        fs_extra::dir::remove(&config_tmp_dir)
            .or(Err(Error::FileError("failed to clean up config temp files")))?;
    }

    // Copy main files
    let to_copy = fs::read_dir(&temp_directory).or(Err(Error::FileError("failed to iterate over downloaded files")))?;
    let to_copy = to_copy.map(|r| r.unwrap().path()).collect();
    fs_extra::copy_items(&to_copy, main_output_directory, &copy_options)
        .or(Err(Error::FileError("failed to overwrite existing files")))?;

    Ok(())
}

pub fn perform_update(remote_url_base: &str) -> Result<(), Error> {
    let temp_directory = "./tmp";

    let remote_manifest_url = format!("{}/version.xml", remote_url_base);
    let update_diff = find_files_needing_update(&remote_manifest_url, "./version.xml", temp_directory)?;

    // Do the actual download
    download_update_files(remote_url_base, temp_directory, update_diff)?;

    // Copy files out
    copy_update_files(temp_directory, "./memes", "./memes")?;

    Ok(())
}