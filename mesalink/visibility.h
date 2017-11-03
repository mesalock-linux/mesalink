/* visibility.h
 *                            _ _       _    
 *                           | (_)     | |   
 *  _ __ ___   ___  ___  __ _| |_ _ __ | | __
 * | '_ ` _ \ / _ \/ __|/ _` | | | '_ \| |/ /
 * | | | | | |  __/\__ \ (_| | | | | | |   < 
 * |_| |_| |_|\___||___/\__,_|_|_|_| |_|_|\_\
 *
 * Copyright (C) 2017 Baidu USA.
 *
 * This file is part of Mesalink.
 */

 /* Visibility control macros */

#ifndef MESALINK_VISIBILITY_H
#define MESALINK_VISIBILITY_H

#define MESALINK_API __attribute__ ((visibility("default")))
#define MESALINK_LOCAL __attribute__ ((visiblity("hidden")))

#endif /* MESALINK_VISIBILITY_H */