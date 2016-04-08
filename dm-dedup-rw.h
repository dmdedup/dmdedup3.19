/*
 * Copyright (C) 2012-2014 Vasily Tarasov
 * Copyright (C) 2012-2014 Geoff Kuenning
 * Copyright (C) 2012-2014 Sonam Mandal
 * Copyright (C) 2012-2014 Karthikeyani Palanisami
 * Copyright (C) 2012-2014 Philip Shilane
 * Copyright (C) 2012-2014 Sagar Trehan
 * Copyright (C) 2012-2014 Erez Zadok
 *
 * This file is released under the GPL.
 */

#ifndef DM_DEDUP_RW_H
#define DM_DEDUP_RW_H

extern struct bio *prepare_bio_on_write(struct dedup_config *dc,
							struct bio *bio);

#endif /* DM_DEDUP_RW_H */
