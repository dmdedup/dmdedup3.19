# dmdedup
Device-mapper Deduplication Target

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
