dm-dedup
========

Device-mapper's dedup target provides transparent data deduplication of block
devices.  Every write coming to a dm-dedup instance is deduplicated against
previously written data.  For datasets that contain many duplicates scattered
across the disk (e.g., virtual machine disk image collections, backups, home
directory servers) deduplication provides a significant amount of space
savings.

Construction Parameters
=======================
	<meta_dev> <data_dev> <block_size>
	<hash_algo> <backend> <flushrq>

<meta_dev>
	This is the device where dm-dedup's metadata resides.  Metadata
	typically includes hash index, block mapping, and reference counters.
	It should be specified as a path, like "/dev/sdaX".

<data_dev>
	This is the device where the actual data blocks are stored.
	It should be specified as a path, like "/dev/sdaX".

<block_size>
	This is the size of a single block on the data device in bytes.
	Block is both a unit of deduplication and a unit of storage.
	Supported values are between 4096 to 1048576 (1MB) and should be
	a power of two.

<hash_algo>
	This specifies which hashing algorithm dm-dedup will use for detecting
	identical blocks, e.g., "md5" or "sha256". Any hash algorithm
	supported by the running kernel can be used (see "/proc/crypto" file).

<backend>
	This is the backend that dm-dedup will use to store metadata.
	Currently supported values are "cowbtree" and "inram".
	Cowbtree backend uses persistent Copy-on-Write (COW) B-Trees to store
	metadata. Inram backend stores all metadata in RAM which is
	lost after a system reboot. Consequently, inram backend should
	typically be used only for experiments. Notice, that though inram
	backend does not use metadata device, <meta_dev> parameter
	should still be specified in the command line.

<flushrq>
	This parameter specifies how many writes to the target should occur
	before dm-dedup flushes its buffered metadata to the metadata device.
	In other words, in an event of power failure, one can loose up to this
	number of most recent writes.  Notice, that dm-dedup also flushes its
	metadata when it sees REQ_FLUSH or REQ_FUA flags in the I/O requests.
	In particular, these flags are set by file systems in the
	appropriate points of time to ensure file system consistency.

During construction, dm-dedup checks if the first 4096 bytes of the metadata
device are equal to zero. If they are, then a completely new dm-dedup instance
is initialized with the metadata and data devices considered "empty". If,
however, 4096 starting bytes are not zero, dm-dedup will try to reconstruct
the target based on the current information on the metadata and data devices.

Theory of Operation
===================

We provide an overview of dm-dedup design in this section. Detailed design and
performance evaluation can be found in the following paper:

V. Tarasov and D. Jain and G. Kuenning and S. Mandal and K. Palanisami and P.
Shilane and S. Trehan. Dmdedup: Device Mapper Target for Data Deduplication.
Ottawa Linux Symposium, 2014.
http://www.fsl.cs.stonybrook.edu/docs/ols-dmdedup/dmdedup-ols14.pdf

To quickly identify duplicates, dm-dedup maintains an index of hashes for all
written blocks.  Block is a user-configurable unit of deduplication and
storage.  Dm-dedup index, along with other deduplication metadata, resides on
a separate block device, which we refer to as metadata device. Blocks
themselves are stored on the data device. Although the metadata device can be
any block device, e.g., an HDD or its partition, for higher performance we
recommend to use SSD devices to store metadata.

For every block that is written to a target, dm-dedup computes its hash using
the <hash_algo>. It then looks for the resulting hash in the hash index. If a
match is found then the write is considered to be a duplicate.

Dm-dedup's hash index is essentially a mapping between the hash and the
physical address of a block on the data device. In addition, dm-dedup
maintains a mapping between logical block addresses on the target and physical
block address on the data device (LBN-PBN mapping). When a duplicate is
detected, there is no need to write actual data to the disk and only LBN-PBN
mapping is updated.

When a non-duplicate data is written, new physical block on the data device is
allocated, written, and a corresponding hash is added to the index.

On read, LBN-PBN mapping allows to quickly locate a required block on the data
device.  If there were no writes to an LBN before, a zero block is returned.

Target Size
-----------

When using device-mapper one needs to specify target size in advance. To get
deduplication benefits, target size should be larger than the data device size
(or otherwise one could just use the data device directly).  Because dataset
deduplication ratio is not known in advance one has to use an estimation.

Usually, up to 1.5 deduplication ratio for a primary dataset is a safe
assumption.  For backup datasets, however, deduplication ratio can be as high
as 100.

Estimating deduplication ratio of an existing dataset using fs-hasher package
from http://tracer.filesystems.org/ can give a good starting point for a
specific dataset.

If one over-estimates deduplication ratio, data device can run out of free
space. This situation can be monitored using dmsetup status command (described
below).  After data device is full, dm-dedup will stop accepting writes until
free space becomes available on the data device again.

Backends
--------

Dm-dedup's core logic considers index and LBN-PBN mappings as plain key-value
stores with an extended API described in

drivers/md/dm-dedup-backend.h

Different backends can provided key-value store API. We implemented a cowbtree
backend that uses device-mapper's persistent metadata framework to
consistently store metadata. Details on this framework and its on-disk layout
can be found here:

Documentation/device-mapper/persistent-data.txt

By using persistent COW B-trees, cowbtree backend guarantees consistency in
the event of power failure.

In addition, we also provide inram backend that stores all metadata in RAM.
Hash tables with linear probing are used for storing the index and LBN-PBN
mapping. Inram backend does not store metadata persistently and should usually
by used only for experiments.

Dmsetup Status
==============

Dm-dedup exports various statistics via dmsetup status command. The line
returned by dmsetup status will contain the following values in the order:

<name> <start> <end> <type> \
<dtotal> <dfree> <dused> <dactual> <dblock> <ddisk> <mddisk> \
<writes><uniqwrites> <dupwrites> <readonwrites> <overwrites> <newwrites>

<name>, <start>, <end>, and <type> are generic fields printed by dmsetup tool
for any target.

<dtotal>       - total number of blocks on the data device
<dfree>        - number of free (unallocated) blocks on the data device
<dused>        - number of used (allocated) blocks on the data device
<dactual>      - number of allocated logical blocks (were written at least once)
<dblock>       - block size in bytes
<ddisk>        - data disk's major:minor
<mddisk>       - metadata disk's major:minor
<writes>       - total number of writes to the target
<uniqwrites>   - the number of writes that weren't duplicates (were unique)
<dupwrites>    - the number of writes that were duplicates
<readonwrites> - the number of times dm-dedup had to read data from the data
		 device because a write was misaligned (read-on-write effect)
<overwrites>   - the number of writes to a logical block that was
		 written before at least once
<newwrites>    - the number of writes to a logical address that was not written
		 before even once

To compute deduplication ratio one needs to device dactual by dused.

Example
=======

Decide on metadata and data devices:
   # META_DEV=/dev/sdX
   # DATA_DEV=/dev/sdY

Compute target size assuming 1.5 dedup ratio:
   # DATA_DEV_SIZE=`blockdev --getsz $DATA_DEV`
   # TARGET_SIZE=`expr $DATA_DEV_SIZE \* 15 / 10`

Reset metadata device:
   # dd if=/dev/zero of=$META_DEV bs=4096 count=1

Setup a target:
	echo "0 $TARGET_SIZE dedup $META_DEV $DATA_DEV 4096 md5 cowbtree 100" |\
				dmsetup create mydedup

Authors
=======

dm-dedup was developed in the File system and Storage Lab (FSL) at Stony
Brook University Computer Science Department, in collaboration with Harvey
Mudd College and EMC.

Key people involved in the project were Vasily Tarasov, Geoff Kuenning,
Sonam Mandal, Karthikeyani Palanisami, Philip Shilane, Sagar Trehan, and
Erez Zadok.

We also acknowledge the help of several students involved in the
deduplication project: Teo Asinari, Deepak Jain, Mandar Joshi, Atul
Karmarkar, Meg O'Keefe, Gary Lent, Amar Mudrankit, Ujwala Tulshigiri, and
Nabil Zaman.
