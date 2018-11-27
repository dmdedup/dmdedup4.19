dm-dedup
=======


The dedup device-mapper target provides transparent inline data deduplication of block devices.  
Every write coming to a dm-dedup instance is deduplicated against previously written data.  
For datasets that contain many duplicates scattered across the disk (e.g., virtual machine disk images, backups, home directory servers) deduplication provides a significant amount of space savings.  
Dm-dedup implements fixed block-size deduplication and supports pluggable backends to manage its metadata.


Construction Parameters
===============
```
<meta_dev> <data_dev> <block_size> <hash_algo> <backend> <flushrq>
```


`<meta_dev>`  
This is the device where dm-dedup's metadata resides.
Metadata typically includes hash index, block mapping, and reference counters.
It should be specified as a path, like `/dev/sdaX`.
We recommend using a faster device for this, such as an SSD.


`<data_dev>`  
This is the device where the actual data blocks are stored.
It should be specified as a path, like `/dev/sdaX`.
We recommend using a larger (and perhaps slower) device for this, such as an HDD or SMR.


`<block_size>`  
This is the size of a single block on the data device in bytes.
Block is both a unit of deduplication and a unit of storage.
Supported values are between `4096 (4KB)` to `1048576 bytes (1MB)` and should be a power of two.


`<hash_algo>`  
This specifies which hashing algorithm dm-dedup will use for detecting identical blocks, e.g., `md5` or `sha256`.
Any hash algorithm supported by the running kernel can be used (see "/proc/crypto" file).


`<backend>`  
This is the backend that dm-dedup will use to store metadata.
Currently supported values are `cowbtree` and `inram`.  
The cowbtree backend uses persistent Copy-on-Write (COW) B-Trees to store metadata.  
The inram backend stores all metadata in RAM which is lost after a system reboot. 
Consequently, inram backend should typically be used only for experiments.  
Note that although the inram backend does not use a metadata device, the `<meta_dev>` parameter should still be specified on the command line.[a][b]


`<flushrq>`  
This parameter specifies how many writes to the target should occur before dm-dedup flushes its buffered metadata to the metadata device.
In other words, in an event of power failure, one can lose up to this number of
most recent writes.  
Note that dm-dedup also flushes its metadata when it sees `REQ_FLUSH` or `REQ_FUA`
flags in the I/O requests.
In particular, these flags are set by file systems at appropriate points of time to ensure file system consistency.
Dm-dedup’s metadata consistency guarantees depend on the specific backend used.
For example, the “cowbtree” backend cannot become inconsistent due to power-failure by design because it uses CoW B-trees.  
  
During construction, dm-dedup checks if the first 4096 bytes of the metadata device are equal to zero.
If they are, then a completely new dm-dedup instance is initialized with the metadata and data devices considered "empty".
If, however, the first 4096 bytes are not zero, dm-dedup will try to reconstruct the target based on the current information on the metadata and data devices.


Overview of Design and Operation
======================


We provide an overview of dm-dedup design in this section. Detailed design and performance evaluation can be found in the following paper:


V. Tarasov and D. Jain and G. Kuenning and S. Mandal and K. Palanisami and P. Shilane and S. Trehan. Dmdedup: Device Mapper Target for Data Deduplication. Ottawa Linux Symposium, 2014.  
[http://www.fsl.cs.stonybrook.edu/docs/ols-dmdedup/dmdedup-ols14.pdf](http://www.fsl.cs.stonybrook.edu/docs/ols-dmdedup/dmdedup-ols14.pdf)



To quickly identify duplicates, dm-dedup maintains an index of hashes for all written  blocks.
The block size is a user-configurable unit of deduplication and storage.
Dm-dedup’s index, along with other deduplication metadata, reside on a separate block device, which we refer to as metadata device.
Data blocks themselves are stored on the data device.
Although the metadata device can be any block device, e.g., an HDD or its partition, for higher performance we recommend to use SSD devices to store metadata.


For every block that is written to a target, dm-dedup computes its hash using the `<hash_algo>`.
It then looks for the resulting hash in the hash index. If a match is found then the write is considered to be a duplicate.


Dm-dedup's hash index is essentially a mapping between the hash and the physical address of a block on the data device (HASH-PBN mapping).
In addition, dm-dedup maintains a mapping between logical block addresses on the target and physical block address on the data device (LBN-PBN mapping).
When a duplicate is detected, there is no need to write actual data to the disk: we create a new LBN-PBN Mapping, and increase a reference count on the corresponding HASH-PBN entry.


When a non-duplicate data is written, a new physical block on the data device is allocated, written, corresponding hash is added to the index, and LBN-PBN mapping is updated.


On read, the LBN-PBN mapping allows to quickly locate a required block on the data device.  If there were no writes to an LBN before, a zero block is returned.


Garbage Collection Module
======================


When dm-dedup’s logical blocks are overwritten, it is possible that old data is no longer referenced from the LBN-PBN mapping; it is still referenced through the HASH-PBN mapping, however.
Dm-dedup, in its current implementation, does not immediately deallocate physical blocks with old, unreferenced data.
Instead, dm-dedup provides a Garbage Collection Module which implements an offline mechanism to free up unreferenced disk space.
PBNs that are referenced only from the hash index will be freed whenever the garbage collection engine is initiated. 


To traverse the HASH-PBNs b-tree, we use linux kernel's `dm_btree_lookup_next`.
This locks the b-tree for traversal and hence stops the I/O operation.
So we provide users with a method to start and stop the garbage collection process.   
This module can be called using device mapper's message interface. 


We can start the garbage collection using the following command:
```
	dmsetup message <dedup_instance> 0 gc_start
```


We can stop the garbage collection using the following command:
```
	dmsetup message <dedup_instance> 0 gc_stop
```


Using `dmsetup status` command a user can get an estimate of the number of blocks that a garbage collection process can reclaim.
This counter is not maintained automatically, however, and the user needs to  run the following command to recalculate the count: 
```
	dmsetup message <dedup_instance> 0 gc_blocks_estimate
```


Corruption Check Module
======================


In case of unexpected system crash, there is a possibility of inconsistencies between the metadata device and data device.
These inconsistencies can be due to corruption of data on data device or some corruption on metadata device.
On device reconstruction, we warn the users to run dmdedup’s corruption check tool if there is a possible inconsistency.
The corruption check tool also finds data corruptions and reports them.


For every read, the module computes the hash of the data of that block and fetches its PBN from the HASH-PBN mapping.
The PBN from the LBN-PBN entry is compared with the fetched PBN to detect discrepancy.
There are 2 possible modes in which this module can work:
1. Corruption Check:  
When enabled reports only corruption. 
2. Forward Error Correction:  
In addition to reporting the corruption, this will try to fix the corruption.
In FEC, if there is discrepancy between the PBN’s from LBN-PBN and from HASH-PBN mapping, then we will be remove the LBN-PBN entry and decrement the refcount of old PBN.
Secondly, we increment the refcount of new PBN and also insert the new LBN-PBN mapping in the btree.
In case, if there is no matching entry found in HASH-PBN, then we insert a new HASH-PBN mapping but it leaves an extra entry in HASH-PBN for old data.


The message to enable Corruption Check mode:
```
	dmsetup message <dedup_instance> 0 corruption 1
```


The message to enable Corruption Check and Forward Error Correction mode:
```
	dmsetup message <dedup_instance> 0 corruption 2
```


The message to disable both Corruption Check and Forward Error Correction mode:
```
	dmsetup message <dedup_instance> 0 corruption 0
```

Trim Support
================
Trim/discard support is very crucial for SSD as well as SCSI disks these days. Hence we have added support for trim/unmap/discard in our mapper device. It discards the blocks which are already deleted and have reference count <= 1. On receiving a discard request, we decrement reference count for that lbn. If reference count reaches 1, it means we can discard that block since it is not being referenced by anyone and hence we forward the discard request to the underlying block device layer. After forwarding request to underlying block device layer it discards those blocks. 

There are many standard utilities available to issue trim command like fstrim and also these requests can be sent at the time of formatting the disk using mkfs utility. 

To discard all unreferenced blocks on mountpoint 
```
sudo fstrim -v /mnt/dedup_mnt
```

To discard blocks while formatting disk using mkfs utitlity.
```
mkfs.ext4 -E discard /dev/mapper/mydedup
```

Target Size
======================


When using device-mapper one needs to specify the target size in advance.
To get deduplication benefits, the target size should be larger than the data device size (or otherwise one could just use the data device directly).
Because the dataset’s deduplication ratio is not known in advance one has to use an estimation.


Usually, up to 1.5 deduplication ratio for a primary dataset is a safe assumption.
For backup datasets, however, deduplication ratio can be as high as 100:1.


Estimating deduplication ratio of an existing dataset using fs-hasher package from [http://tracer.filesystems.org/](http://tracer.filesystems.org/) can give a good starting point for a specific dataset.


If one overestimates the deduplication ratio, the data device can run out of physical free space.
This situation can be monitored using dmsetup status command (described below).
After the data device is full, dm-dedup will stop accepting writes until free space becomes available on the data device again.


Backends
======================


Dm-dedup's core logic considers index and LBN-PBN mappings as plain key-value stores with an extended API described in 
```
drivers/md/dm-dedup-backend.h.
```


Different backends can provided a key-value store API.
We implemented a cowbtree backend that uses device-mapper's persistent metadata framework to consistently store metadata.
Details on this framework and its on-disk layout can be found here:
```
Documentation/device-mapper/persistent-data.txt
```


By using persistent COW B-trees, cowbtree backend guarantees consistency in the event of power failure.


In addition, we also provide an inram backend that stores all metadata in RAM.
Hash tables with linear probing are used for storing the index and LBN-PBN mapping.
The inram backend does not store metadata persistently and should usually be used only for experiments.


Dmsetup Status
==========


Dm-dedup exports various statistics via dmsetup status command. The line returned by dmsetup status will contain the following values in the order:

```
<name> <start> <end> <type> \
<dtotal> <dfree> <dused> <dactual> <dblock> <ddisk> <mddisk> \
<writes><uniqwrites> <dupwrites> <readonwrites> <overwrites> \
<newwrites> <gcblocksestimate> <gcblockscleaned> <gcstatus>


<name>, <start>, <end>, and <type> are generic fields printed by dmsetup tool for any target.


<dtotal>		- total number of blocks on the data device
<dfree>			- number of free (unallocated) blocks on the data device
<dused>			- number of used (allocated) blocks on the data device
<dactual>		- number of allocated logical blocks (were written at least once)
<dblock>		- block size in bytes
<ddisk>			- data disk's major:minor
<mddisk>		- metadata disk's major:minor
<writes>		- total number of writes to the target
<uniqwrites>		- the number of writes that weren't duplicates (were unique)
<dupwrites>		- the number of writes that were duplicates
<readonwrites>		- the number of times dm-dedup had to read data from the data
			  device because a write was misaligned (read-on-write effect)
<overwrites>		- the number of writes to a logical block that was written before
			  at least once
<newwrites>		- the number of writes to a logical address that was not written 
			  before even once
<gcblocksestimate>	- total number of garbage blocks
<gcblockscleaned>	- total number of blocks garbage collected        
<gcstatus>		- status whether garbage collection is currently going on or not
```
To compute deduplication ratio one needs to divide `<dactual>` by `<dused>`.


Example
======


Decide on metadata and data devices:
```
	# META_DEV=/dev/sdX
	# DATA_DEV=/dev/sdY
```


Compute target size assuming 1.5 dedup ratio:
```
	# DATA_DEV_SIZE=`blockdev --getsz $DATA_DEV`
	# TARGET_SIZE=`expr $DATA_DEV_SIZE \* 15 / 10`
```


Reset metadata device:
```
	# dd if=/dev/zero of=$META_DEV bs=4096 count=1
```


Setup a target:
```
	echo "0 $TARGET_SIZE dedup $META_DEV $DATA_DEV 4096 md5 cowbtree 100" |\
		dmsetup create mydedup
```


Authors
=====


dm-dedup was developed in the File system and Storage Lab (FSL) at Stony Brook University Computer Science Department, in collaboration with Harvey Mudd College and Dell-EMC.


Key people involved in the project were Vasily Tarasov, Geoff Kuenning, Sonam Mandal, Karthikeyani Palanisami, Philip Shilane, Sagar Trehan, and Erez Zadok.


We also acknowledge the help of several students involved in the deduplication project: Teo Asinari, Deepak Jain, Mandar Joshi, Atul Karmarkar, Gary Lent, Amar Mudrankit, Meg O'Keefe, Nidhi Panpalia, Vinothkumar Raja, Noopur Maheshwari, Rahul Rane, Ujwala Tulshigiri and Nabil Zaman.
