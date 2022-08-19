#!/bin/bash

# defaults
retries=5
verbose=0

print_msg (){
    echo "********************************************************************************"
    echo "---------- $1"
    echo "********************************************************************************"
}

usage() {
    print_msg "Usage: $0 [-r <none|direct|sgx>] [-n <RESULT_RAW_NAME>] [-i <RETRIES=10>] [-v] -- PERF_CLIENT_ARGS"
    exit 1
}

write_results_to_file (){
    popd
    if [ ! -f "$results_file" ]; then
        print_msg "Writing results to $results_file"
        echo -e $header_row > $results_file
    else
        print_msg "Appending results to $results_file"
    fi
    echo -e $result_row >> $results_file
}

trap_int (){
    print_msg "Writing what we have so far to $results_file"
    write_results_to_file
    exit 1
}

while getopts "r:n:i:v" o; do
    case "${o}" in
        r)
            runtime_env="${OPTARG}"
            [[ "$runtime_env" =~ ^(none|direct|sgx)$ ]] || usage
            ;;
        n)
            result_row_name="${OPTARG}"
            ;;
        i)
            retries=${OPTARG}
            ;;
        v)
            verbose=1
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "$runtime_env" ] || [ -z "$result_row_name" ]; then
    usage
fi

batch_sizes=( 1 2 4 5 8 10 16 20 25 40 50 80 100 125 200 250 400 500 625 1000)
results_file="results-`date -I`.csv"
header_row="batch_sizes"
result_row="$result_row_name"
prefix="taskset -c 10"
if [ "$runtime_env" = "direct" ]; then
    prefix="$prefix gramine-direct"
elif [ "$runtime_env" = "sgx" ]; then
    prefix="$prefix gramine-sgx"
fi

pushd src
    trap trap_int INT

    for bs in ${batch_sizes[@]}
    do
        print_msg "Now testing with batch size: $bs"
        header_row="${header_row},$bs"
        accumulated_thrgpt=0
        for r in $(seq $retries)
        do
            output="$($prefix ./perf-client -b $bs $@)"
            es=$?
            if [ $es -ne 0 ]; then
                print_msg "perf-client failed. Aborting test.";
                exit $es
            else
                if [ $verbose -eq 1 ]; then
                    echo -e "$output"
                fi
            fi

            thrgpt=$(echo "$output" | awk '/Iterations average byte throughput:/ {print $7}')
            print_msg "Run throughput: $thrgpt Mbps"

            accumulated_thrgpt=$(( $accumulated_thrgpt + $thrgpt ))
            sleep .5
        done

        avg_thrgpt=$(( $accumulated_thrgpt / $retries ))
        print_msg "Batch size ($bs) average throughput: $avg_thrgpt Mbps"

        result_row="${result_row},$avg_thrgpt"
        sleep .5
    done

    write_results_to_file
popd

print_msg "Done!"
