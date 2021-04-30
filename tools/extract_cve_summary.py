#!/usr/bin/env python3
from git_vuln_finder import find
from git import Repo
from shutil import move
from datetime import datetime
import json
import argparse
import requests
import subprocess
import sys
import time
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TARGETS_FILE = "targets.json"
ERROR_COLOR= "\033[91m"
WARN_COLOR= "\033[33m"
END_COLOR= "\033[0m"

def parse_arguments():
    parser = argparse.ArgumentParser(description="get cve summary from git repository")
    parser.add_argument("repo_path", type=str, help="repository that gets searched for CVE patches")
    parser.add_argument("build_file_path", type=str, help="program that builds the target that is used for fuzzing (must be able to take repo_path as first argument)")
    parser.add_argument("-d", action="store", dest="download_link", help="fetch repository from given link and place it in repo_path location")
    parser.add_argument("-sa", action="store_const", const=True, default=False, dest="show_all", help="show all vulnerabilities (even without CVE)")
    parser.add_argument("-so", action="store_const", const=True, default=False, dest="show_only", help="only show the vulnerabilities, other flags related to downloading and fuzzing will be ignored")
    parser.add_argument("-t", action="store", type=int, default=60, dest="timeout", help="fuzzer timeout in seconds (default 60)")
    parser.add_argument("-r", action="store_const", const=True, default=False, dest="classify_all", help="go through every security patch for classification")
    parser.add_argument("-D", action="store_const", const=True, default=False, dest="debug_env", help="enable backtrace and debug logging for the parmesan fuzzer")
    parser.add_argument("-f", action="store_const", const=True, default=False, dest="fuzz_only", help="skip building and fetching targets, go straight to fuzzing")
    parser.add_argument("-c", action="store", dest="commit_id", help="Use a given commit to classify")
    parser.add_argument("-b", action="store", type=str, default="", dest="branch", help="change the git branch")
    # parser.add_argument("-ca", action="store", type=str, default="", dest="clone_arguments", help="clone arguments when using a git repository. This is where you would specify attributes like 'depth' or 'branch'")
    return parser.parse_args()

def extract_cve_summary(cves, commit_date):
    # remove duplicates
    cves = list(dict.fromkeys(cves))
    # get date
    date = datetime.utcfromtimestamp(commit_date).strftime('%Y-%m-%d')
    # get all summaries from cve database
    database_summaries = {}
    for cve in cves:
        database_summaries['date'] = date
        database_summaries["cve_id"] = cve
        r = requests.get("https://cve.circl.lu/api/cve/" + cve)
        if r.status_code != 200:
            print(r, "moving on")
            continue
        r = r.json()
        database_summaries["cve_summary"] = r["summary"]
    # print(database_summaries)
    return database_summaries

def search_repo(repo_path, show_all):
    all_potential_vulnerabilities, _, _ = find(repo_path)
    if show_all:
        # vulns = json.dumps(all_potential_vulnerabilities, sort_keys=True, indent=4, separators=(",", ": "))
        # print(vulns)
        # cve_summary is not really CVE summary...
        return [(commit, {'cve_id': '-', 
            'cve_summary': summary["summary"], 
            'date': datetime.utcfromtimestamp(summary['committed_date']).strftime('%Y-%m-%d')}) for commit, summary in all_potential_vulnerabilities.items()]
    else:
        return [(commit, extract_cve_summary(summary["cve"], summary["committed_date"])) for commit, summary in all_potential_vulnerabilities.items() if summary['state'] == 'cve-assigned']

    
    # print(json.dumps(all_potential_vulnerabilities['9069838b30fb3b48af0123e39f664cea683254a5'], sort_keys=True, indent=4, separators=(",", ": ")))

def fetch_repo(download_link, repo_path, commit_branch):
    # check if specific branch must be fetched
    if (commit_branch):
        multi_options_value = ['--branch ' + commit_branch]
        # print("MULTI-OPTIONS-VALUE: ", multi_options_value)
        Repo.clone_from(download_link, repo_path, multi_options=multi_options_value)
    else:
        Repo.clone_from(download_link, repo_path)

def build(repo_path, build_file_path):
    process = subprocess.Popen([build_file_path, repo_path])
    process.communicate()
    rc = process.returncode
    if (rc == 1) :
        print("Build failed: exiting!")
        exit(1)

def extract_targets(repo_path, unpatched_repo_path):
    print("REPO PATH:", repo_path)
    print("UNPATCHED REPO PATH:", unpatched_repo_path)
    program = []
    program.append(os.environ["PARM_BIN"])
    if program[0][-1] == "/":
        program[0] = program[0] + "llvm-diff-parmesan"
    else:
        program[0] = program[0] + "/llvm-diff-parmesan"
    program.append("-json")
    BASENAME = os.path.basename(unpatched_repo_path)
    DIRNAME = os.path.dirname(unpatched_repo_path)
    PATHNAME = DIRNAME + "/OUT/" + BASENAME
    program.append(SCRIPT_DIR + "/" + PATHNAME + ".ll")
    BASENAME = os.path.basename(repo_path)
    DIRNAME = os.path.dirname(repo_path)
    PATHNAME = DIRNAME + "/OUT/" + BASENAME
    program.append(SCRIPT_DIR + "/" + PATHNAME + ".ll")

    # program.append("2> /dev/null")
    
    print("PROGRAM", program)
    with open("patch.diff", "w") as diff_file:
        process = subprocess.Popen(program, stderr=diff_file)
        process.communicate()

    # Copy generated targets.json and patch.diff to the targets directory
    move(SCRIPT_DIR + "/targets.json", SCRIPT_DIR + "/" + DIRNAME + "/OUT/targets.json")
    move(SCRIPT_DIR + "/patch.diff", SCRIPT_DIR + "/" + DIRNAME + "/OUT/patch.diff")

def fuzz(unpatched_repo_path, timeout, debug_env):
    # Build up the fuzzing program to execute as subprocess
    fuzzing_program = []

    fuzzer = os.environ["PARM_BIN"]
    if fuzzer[-1] == "/":
        fuzzer = fuzzer + "fuzzer"
    else:
        fuzzer = fuzzer + "/fuzzer"

    # Normalized basename to reference proper paths
    DIRNAME = "/" + os.path.dirname(unpatched_repo_path)
    OUT_DIR = DIRNAME + "/OUT/"
    BASENAME = os.path.basename(unpatched_repo_path)

    # time limit is PER INPUT, not the total time
    time_limit = ["-T", "2"]
    targets_file = ["--cfg", SCRIPT_DIR + OUT_DIR + "targets.json"]
    input_dir = ["-i", SCRIPT_DIR + OUT_DIR + "input"]
    output_dir = ["-o", SCRIPT_DIR + OUT_DIR + "output"]
    track_file = ["-t", SCRIPT_DIR + OUT_DIR + BASENAME + ".track"]
    # TODO custom ARGS list
    fast_file = ["--", SCRIPT_DIR + OUT_DIR + BASENAME + ".fast", "@@"]

    env = os.environ.copy()
    # fuzzer debug
    if (debug_env):
        env["RUST_BACKTRACE"] = "1"
        env["RUST_LOG"] = "debug"
    fuzzing_program = [fuzzer] + time_limit + targets_file + input_dir + output_dir + track_file + fast_file
    print(fuzzing_program)

    process = subprocess.Popen(fuzzing_program, env=env)
    process.communicate
    return process

def classify(vuln, repo_path, download_link, commit_branch, build_file_path, timeout, debug_env, fuzz_only):

    unpatched_repo_path = repo_path + "-unpatched"
    if (not fuzz_only):
        # Get both the patched and unpacthed version
        # Most recent commit has already been fetched, checkout to the patched version
        patched_commit = vuln[0]
        patched_repo = Repo(repo_path)
        assert not patched_repo.bare
        #patched_repo.commit(patched_commit)
        patched_repo.create_head('patched_branch', patched_commit)
        patched_repo.heads.patched_branch.checkout()

        # Fetch another repo and set the commit to the one before the patched one
        fetch_repo(download_link, unpatched_repo_path, commit_branch)
        unpatched_repo = Repo(unpatched_repo_path)
        assert not unpatched_repo.bare
        # One back
        unpatched_repo.create_head('unpatched_branch', patched_commit + "^")
        unpatched_repo.heads.unpatched_branch.checkout()

        print("Building... (1/2)")
        build(repo_path, build_file_path)

        print("Building... (2/2)")
        build(unpatched_repo_path, build_file_path)

        print("Targets built! Extracting targets")
        extract_targets(repo_path, unpatched_repo_path)

    process = fuzz(unpatched_repo_path, timeout, debug_env)

    print("Fuzzing for {:2d} seconds".format(timeout))
    for remaining in range(timeout, -1, -1):
        sys.stdout.write("\r")
        sys.stdout.write("{:2d} minutes and {:2d} seconds remaining".format(int(remaining/60), remaining % 60))
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\n")
    process.terminate()

    print("Done!")

def classify_print_vulns(vulns):
    # Print all vulnerabilities
    print("{:<19} {:<20} {:<20} {:<20}".format(f"{ERROR_COLOR}OPTION{END_COLOR}", "CVE ID", "DATE", "SUMMARY"))
    
    for i, vuln in enumerate(vulns):
        print("{:<10} {:<20} {:<20} {:<20}".format(str(i), vuln[1]["cve_id"], vuln[1]["date"], vuln[1]["cve_summary"]))

def classify_commit_id(args):
    if (args.classify_all):
        print(f"{WARN_COLOR}WARNING{END_COLOR}: skipping classify all as specific commit ({args.commit_id}) is given.")
    vulnerability = [args.commit_id, {}]
    classify(vulnerability, norm_repo_path, args.download_link, args.branch, args.build_file_path, args.timeout, args.debug_env, args.fuzz_only)

def classify_all(vulns, args):
    # Try to classify all vulnerabilities
    for i, vuln in enumerate(vulns):
        print("Processing vulnerability", i, ": ", vuln)
        classify(vuln, norm_repo_path, args.download_link, args.branch, args.build_file_path, args.timeout, args.debug_env, args.fuzz_only)

def classify_option_choice_loop(vulns, num_vulns):
    classify_print_vulns(vulns)

    # Choice loop
    while(1):
        potential_input = input(f'Choose one {ERROR_COLOR} OPTION {END_COLOR} to start classifying: ')
        try:
            int(potential_input)
        except ValueError:
            print(f'{ERROR_COLOR} ERROR {END_COLOR}: Option not a valid integer, try again')
            continue
        valid_int = int(potential_input)
        if (valid_int >= 0 and valid_int < num_vulns):
            return valid_int
        else:
            print(f'{ERROR_COLOR} ERROR {END_COLOR}: Option not in range, try again')


def classify_option(vulns, args):
    num_vulns = len(vulns)
    # early exit
    if (num_vulns == 0):
        print("No vulnerabilities found using git vulnerability finder. Use -sa flag to find more vulnerabilities, or give a specific commit ID using -c [COMMIT_ID].")
        exit(0)

    valid_option_num = classify_option_choice_loop(vulns, num_vulns)
    
    valid_option = vulns[valid_option_num]
    classify(valid_option, norm_repo_path, args.download_link, args.branch, args.build_file_path, args.timeout, args.debug_env, args.fuzz_only)

if __name__ == "__main__":

    args = parse_arguments()

    if (args.download_link and not args.fuzz_only and not args.show_only):
        fetch_repo(args.download_link, args.repo_path, args.branch)

    # Normalize the repo_path
    norm_repo_path = os.path.normpath(args.repo_path)

    # extract_cve_summary(['CVE-2019-15601', 'CVE-2019-15601'])
    vulnerabilities = search_repo(norm_repo_path, args.show_all)

    # Classify a specific commit, classify all vulnerabilities, or print out a list of vulnerabilities to classify.
    if (args.show_only):
        classify_print_vulns(vulnerabilities)
    elif (args.commit_id):
        classify_commit_id(args)
    elif (args.classify_all):
        classify_all(vulnerabilities, args)
    else:
        classify_option(vulnerabilities, args)