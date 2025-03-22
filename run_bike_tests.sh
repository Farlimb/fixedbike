#!/bin/bash

# Create directory for binary data files if it doesn't exist
mkdir -p bike_data

# Create CSV files with headers
echo "Iteration,Time (s),Memory Before (KB),Memory After (KB),Memory Used (KB)" > keygen_measurements.csv
echo "Iteration,Time (s),Memory Before (KB),Memory After (KB),Memory Used (KB)" > encaps_measurements.csv
echo "Iteration,Time (s),Memory Before (KB),Memory After (KB),Memory Used (KB),Correct" > decaps_measurements.csv

# Function to display progress bar
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r[%s%s] %d%% (%d/%d)" "$(printf '#%.0s' $(seq 1 $completed))" "$(printf ' %.0s' $(seq 1 $remaining))" "$percentage" "$current" "$total"
}

echo "Starting BIKE measurement tests (100 iterations)"
echo "----------------------------------------------"

# Run 100 iterations of the full KEM process
for i in {1..100}; do
    # Show progress
    show_progress $i 100
    
    # Run key generation and capture output
    keygen_output=$(./bike-demo-test_keygen 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\nError in key generation at iteration $i"
        exit 1
    fi
    echo "$i,$keygen_output" >> keygen_measurements.csv
    
    # Small delay to ensure files are written
    sleep 0.1
    
    # Run encapsulation and capture output
    encaps_output=$(./bike-demo-test_encaps 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\nError in encapsulation at iteration $i"
        exit 1
    fi
    echo "$i,$encaps_output" >> encaps_measurements.csv
    
    # Small delay to ensure files are written
    sleep 0.1
    
    # Run decapsulation and capture output
    decaps_output=$(./bike-demo-test_decaps 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "\nError in decapsulation at iteration $i"
        exit 1
    fi
    echo "$i,$decaps_output" >> decaps_measurements.csv
done

echo -e "\nAll measurements completed successfully!"

# Calculate averages for each measurement
echo "----------------------------------------------"
echo "Calculating statistics..."

# Function to calculate average from a column in CSV
calculate_average() {
    local file=$1
    local column=$2
    local skip_header=$3
    local start_line=1
    
    if [ "$skip_header" = true ]; then
        start_line=2
    fi
    
    awk -F, -v col="$column" -v start="$start_line" 'NR>=start {sum+=$col; count++} END {print sum/count}' "$file"
}

# Calculate and display averages
keygen_time_avg=$(calculate_average keygen_measurements.csv 2 true)
keygen_mem_avg=$(calculate_average keygen_measurements.csv 5 true)
encaps_time_avg=$(calculate_average encaps_measurements.csv 2 true)
encaps_mem_avg=$(calculate_average encaps_measurements.csv 5 true)
decaps_time_avg=$(calculate_average decaps_measurements.csv 2 true)
decaps_mem_avg=$(calculate_average decaps_measurements.csv 5 true)

echo "Average Key Generation Time: ${keygen_time_avg} seconds"
echo "Average Key Generation Memory: ${keygen_mem_avg} KB"
echo "Average Encapsulation Time: ${encaps_time_avg} seconds"
echo "Average Encapsulation Memory: ${encaps_mem_avg} KB"
echo "Average Decapsulation Time: ${decaps_time_avg} seconds"
echo "Average Decapsulation Memory: ${decaps_mem_avg} KB"

# Create a summary CSV file
echo "Creating summary file..."
echo "Operation,Average Time (s),Average Memory (KB)" > bike_summary.csv
echo "Key Generation,${keygen_time_avg},${keygen_mem_avg}" >> bike_summary.csv
echo "Encapsulation,${encaps_time_avg},${encaps_mem_avg}" >> bike_summary.csv
echo "Decapsulation,${decaps_time_avg},${decaps_mem_avg}" >> bike_summary.csv

echo "----------------------------------------------"
echo "Results saved to:"
echo "  - keygen_measurements.csv"
echo "  - encaps_measurements.csv"
echo "  - decaps_measurements.csv"
echo "  - bike_summary.csv"