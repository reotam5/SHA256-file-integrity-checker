#!/bin/bash
readonly DIRECTORY=/etc
readonly EXCLUDES='^(~\$.*|.*\.(tmp|temp|bak)$|.*~$)'
readonly BASELINE=/tmp/8003_asn6/etc_hashes.txt
readonly LOG_FILE=/tmp/8003_asn6/integrity_report.log

function clear_baseline () {
    local baseline=$1
    if [[ -f $baseline ]]; then
        rm $baseline
    fi
}

function compute_hashes () {
    local current_directory=$1
    local save_to=$2

    for basename in $(ls -A "$current_directory"); do
        full_path="$current_directory/$basename"

        if echo $basename | grep -qE $EXCLUDES; then
            continue
        fi

        if [[ -d $full_path && -r $full_path ]]; then
            compute_hashes $full_path $save_to
        fi

        if [[ -f $full_path && -r $full_path ]]; then
            sha256sum $full_path >> $save_to
        fi
    done
}

function compare_files () {
    local file1=$1
    local file2=$2

    if [[ ! -f $LOG_FILE ]]; then
        mkdir -p $(dirname $LOG_FILE)
        touch $LOG_FILE
    fi

    local modified=()
    local added=()
    local removed=()

    while IFS= read -r line_file1; do
        file_path=$(echo $line_file1 | awk '{print $2}')
        line_file2=$(grep -w "$file_path" $file2)

        hash_file1=$(echo $line_file1 | awk '{print $1}')
        hash_file2=$(echo $line_file2 | awk '{print $1}')

        if [[ -z $line_file2 ]]; then
            removed+=($file_path)
        elif [[ $hash_file1 != $hash_file2 ]]; then
            modified+=($file_path)
        fi
    done < $file1

    while IFS= read -r line_file2; do
        file_path=$(echo $line_file2 | awk '{print $2}')
        if ! grep -qw "$file_path" $file1; then
            added+=($file_path)
        fi
    done < $file2

    timestamp=$(date '+%s')
    log_entry="$(date '+%s')\tMODIFIED:$(IFS=", "; echo "${modified[*]}")\tADDED:$(IFS=", "; echo "${added[*]}")\tREMOVED:$(IFS=", "; echo "${removed[*]}")"
    echo -e $log_entry >> $LOG_FILE

    if [[ ! -z $modified || ! -z $added || ! -z $removed ]]; then
        email_body="Timestamp: $timestamp\n"
        for action in "modified" "added" "removed"; do
            array_name="${action}[@]"
            files=("${!array_name}")

            if [[ ${#files[@]} -gt 0 ]]; then
                email_body="$email_body\n$action (${#files[@]}):"
                for file in "${files[@]}"; do
                    email_body="$email_body\n\t$file"
                done
            fi
        done

        echo -e "$email_body" | mail -s "Integrity check failed" $(whoami)

        if [[ $run_report == false ]]; then
            echo "Some files were added/removed/modified since last baseline was created. Use --report to see more details."
        else
            display_report
        fi
        exit 1

    else
        if [[ $run_report == false ]]; then
            echo "No changes detected"
        fi
    fi
}

function display_report () {
    if [[ ! -f $LOG_FILE ]]; then
        echo "No report found."
        exit 1
    else
        line=$(tail -n 1 $LOG_FILE)

        # Extract the timestamp, modified, added, and removed files. Remove trailing spaces
        timestamp=$(echo $line | awk '{print $1}' | sed "s/[[:space:]]*$//")
        modified=$(echo $line | awk -F 'MODIFIED:' '{print $2}' | awk -F 'ADDED:' '{print $1}' | sed "s/[[:space:]]*$//")
        added=$(echo $line | awk -F 'ADDED:' '{print $2}' | awk -F 'REMOVED:' '{print $1}' | sed "s/[[:space:]]*$//")
        removed=$(echo $line | awk -F 'REMOVED:' '{print $2}' | sed "s/[[:space:]]*$//")

        echo "Timestamp: $timestamp"

        if [[ -z $modified && -z $added && -z $removed ]]; then
            echo "No changes detected"
        else
            [[ ! -z $modified ]] && echo "Modified: $modified" || echo "Modified: None"
            [[ ! -z $added ]] && echo "Added: $added" || echo "Added: None"
            [[ ! -z $removed ]] && echo "Removed: $removed" || echo "Removed: None"
        fi
    fi
}


function generate_baseline () {
    if [[ ! -d $DIRECTORY || ! -r $DIRECTORY ]]; then
        echo "$DIRECTORY is not a valid directory"
        exit 1
    fi
    if [[ ! -f $BASELINE ]]; then
        mkdir -p $(dirname $BASELINE)
        touch $BASELINE
    fi

    clear_baseline $BASELINE
    compute_hashes $DIRECTORY $BASELINE
}

function check_integrity () {
    if [[ ! -f $BASELINE ]]; then
        echo "Baseline not found. Please generate a baseline first using --baseline option"
        exit 1
    fi
    temp_file=$(mktemp)
    compute_hashes $DIRECTORY $temp_file
    compare_files $BASELINE $temp_file
    rm $temp_file
}


function display_help () {
    if [[ ! -z $1 ]]; then
        echo "Unknown option: $1"
    fi
    echo "Usage: $0 [OPTION]"
    echo "Options:"
    echo "  --baseline: Generate a new baseline"
    echo "  --check: Check the integrity of the system and log the result"
    echo "  --report: Display the last integrity check report"
}


run_baseline=false
run_check=false
run_report=false

if [[ $# -eq 0 ]]; then
    display_help
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline) run_baseline=true ;;
        --check) run_check=true ;;
        --report) run_report=true ;;
        *)
            display_help $1
            exit 1
            ;;
    esac
    shift
done

if [[ $run_baseline == true ]]; then
    generate_baseline
fi
if [[ $run_check == true ]]; then
    check_integrity
fi
if [[ $run_report == true ]]; then
    display_report
fi

