/*
 * Copyright © 2017-2018 Dover Microsystems, Inc.
 * All rights reserved. 
 *
 * Use and disclosure subject to the following license. 
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <map>
#include "tag_file.h"
#include "uleb.h"

using namespace policy_engine;

struct file_reader_t {
  FILE *fp;
  file_reader_t(FILE *fp) : fp(fp) { }
  bool read_byte(uint8_t &b) {
    return fread(&b, 1, 1, fp) == 1;
  }
};

struct file_writer_t {
  FILE *fp;
  file_writer_t(FILE *fp) : fp(fp) { }
  bool write_byte(uint8_t &b) {
    return fwrite(&b, 1, 1, fp) == 1;
  }
};

bool policy_engine::load_tags(metadata_memory_map_t *map, std::string file_name) {
  FILE *fp = fopen(file_name.c_str(), "rb");

  if (!fp)
    return false;

  file_reader_t reader(fp);
  fseek(fp, 0, SEEK_END);
  size_t eof_point = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  
  while (eof_point != ftell(fp)) {
    address_t start;
    address_t end;
    uint32_t metadata_count;

    if (!read_uleb<file_reader_t, uint32_t>(&reader, start)) {
      fclose(fp);
      return false;
    }
    if (!read_uleb<file_reader_t, uint32_t>(&reader, end)) {
      fclose(fp);
      return false;
    }
    if (!read_uleb<file_reader_t, uint32_t>(&reader, metadata_count)) {
      fclose(fp);
      return false;
    }
    //printf("tagfile read (0x%x, 0x%x): %d meta_t\n", start, end, metadata_count);
    metadata_t *metadata = new metadata_t();
    for (uint32_t i = 0; i < metadata_count; i++) {
      meta_t meta;
      if (!read_uleb<file_reader_t, meta_t>(&reader, meta)) {
	fclose(fp);
	delete metadata;
	return false;
      }
      metadata->insert(meta);
    }
    map->add_range(start, end, metadata);
  }
  fclose(fp);
  return true;
}

// Creates a map that maps addresses to vectors of field values to set on those addresses.
// Map is created based on content of taginfo.args file that is loaded automatically.
arg_val_map_t * policy_engine::load_tag_args(metadata_memory_map_t *map, std::string file_name) {
  
  printf("Loading tag arguments file %s\n", file_name.c_str());

  arg_val_map_t * tag_arg_map = new std::map<uint32_t, std::vector<uint32_t>*>();
  
  // Read taginfo.args file. Current format is just ASCII.
  try {
    
    std::string line;    
    std::ifstream infile(file_name);
    if (infile.fail()){
      printf("Warning: did not find taginfo.args file. No argument set.\n");
      return tag_arg_map;
    }
    
    while (std::getline(infile, line)) {

      // Cut into tokens
      std::istringstream iss(line);
      std::vector<std::string> tokens {std::istream_iterator<std::string>{iss},
	  std::istream_iterator<std::string>{}};
      
      //printf("Line = '%s', numtokens=%lu\n", line.c_str(), tokens.size());
      if (tokens.size() < 2){
	printf("Bad line, less than two tokens: %s\n", line.c_str());
	continue;
      }
      
      // Extract start and end
      address_t start;
      address_t end;
      start = strtol(tokens[0].c_str(), 0, 16);
      end = strtol(tokens[1].c_str(), 0, 16);

      // Make vector out of argument ints
      std::vector<uint32_t> * argument_values = new std::vector<uint32_t>();
      for (int i = 2; i < tokens.size(); i++){
	uint32_t arg_val = strtol(tokens[i].c_str(), 0, 10);
 	argument_values -> push_back(arg_val);
      }

      // Add to map on each address
      uint32_t current;
      for (current = start; current < end; current +=4 ){
	//printf("Adding to tag arg map on addr %d\n", current);
	tag_arg_map -> insert(std::pair<uint32_t, std::vector<uint32_t>*>(current, argument_values));
      }
    }
  } catch (...) {
    fprintf(stderr, "error loading %s\n", file_name.c_str());
    return NULL;
  }  
  return tag_arg_map;
}

bool policy_engine::save_tags(metadata_memory_map_t *map, std::string file_name) {
  FILE *fp = fopen(file_name.c_str(), "wb");

  if (!fp)
    return false;
  file_writer_t writer(fp);
  for (auto &e: *map) {
    if (!write_uleb<file_writer_t, uint32_t>(&writer, e.first.start)) {
      fclose(fp);
      return false;
    }
    if (!write_uleb<file_writer_t, uint32_t>(&writer, e.first.end)) {
      fclose(fp);
      return false;
    }
    if (!write_uleb<file_writer_t, uint32_t>(&writer, e.second->size())) {
      fclose(fp);
      return false;
    }
    for (auto &m: *e.second) {
      if (!write_uleb<file_writer_t, meta_t>(&writer, m)) {
	fclose(fp);
	return false;
      }
    }
  }
  fclose(fp);
  return true;
}
