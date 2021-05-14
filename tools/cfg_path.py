#!/usr/bin/env python3
# Helper tool to find all paths to specific CMPID node in cfg file.
import argparse
import ast

def parse_arguments():
    parser = argparse.ArgumentParser(description="get cve summary from git repository")
    parser.add_argument("cfg_file_path", type=str, help="file that contains the cfg")
    parser.add_argument("destination", action="store", type=int, default=0, help="destination that the paths lead to")
    parser.add_argument("--delete-subpaths", action="store_const", const=True, default=False, dest="del_subpaths", help="Only show 'main paths' (deletes all paths that are part of the main paths)")
    return parser.parse_args()

def read_file(cfg_file_path):
    with open(cfg_file_path, "r") as f:
        content = f.read()
        cfg_dict = ast.literal_eval(content)
    return cfg_dict

def find_paths(cfg, dest):
    cfg_edges = cfg["edges"]
    all_paths = [[dest]]
    cur_path_index = 0
    # cur_node = all_paths[cur_path_index][0]
    completed_paths = 0

    # depth-first backwards walk while there are paths to complete
    while completed_paths < len(all_paths):
        cur_node = all_paths[cur_path_index][0]
        prev_nodes = [x[0] for x in cfg_edges if x[1] == cur_node and x[0] != x[1] and x[0] not in all_paths[cur_path_index]]
        # if there are no previous nodes we must be at the beginning and thus completed the path
        if len(prev_nodes) == 0:
            completed_paths += 1
            cur_path_index += 1
        
        if len(prev_nodes) == 1:
            all_paths[cur_path_index].insert(0, prev_nodes[0])

        if len(prev_nodes) > 1:
            all_paths[cur_path_index].insert(0, prev_nodes[0])
            for i, prev_node in enumerate(prev_nodes):
                if i == 0:
                    continue
                all_paths.append([prev_node] + all_paths[cur_path_index])


    # print(all_paths)
    return all_paths

def show_paths(paths):
    for i, path in enumerate(paths):
        print(f"PATH {i}:")
        for node in path:
            print(f"{node}, ", end="")
        print("")

def delete_subpaths(paths):
    if len(paths) < 2:
        return paths

    new_paths = []

    for path1 in paths:
        for j, path2 in enumerate(paths):
            if path1 == path2:
                continue

            path1fin2 = path1[0] in path2
            path1lin2 = path1[-1] in path2
            path2fin1 = path2[0] in path1
            path2lin1 = path2[-1] in path1

            #  and path2.index(path1[0]) != 0
            if path1fin2 and path1lin2:
                break

        if j == len(paths) -1:
            #ONLY EVER ADD PATH1 TO NEW_PATHS
            new_paths.append(path1)
    
    return new_paths

if __name__ == "__main__":

    args = parse_arguments()

    cfg_dict = read_file(args.cfg_file_path)
    paths = find_paths(cfg_dict, args.destination)
    if args.del_subpaths:
        paths = delete_subpaths(paths)
    show_paths(paths)