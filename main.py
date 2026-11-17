"""!
@file main.py
@brief Reads a server access log, analyzes login statuses, and
writes a security report
@author  Henry Meadows
@date  November 17, 2026
"""

def analyze_logs(filename) -> tuple | None:
    """
    @brief Analyze the logs
    :param filename: Path to the log file
    :return: Tuple of (total_attempts, failed_count, locked_count),
    or None if no logs found
    """
    total_attempts = 0
    failed_count = 0
    locked_count = 0

    try:
        with open(filename, "r", encoding="utf-8") as in_file:
            for line in in_file:
                clean_line = line.strip()
                if not clean_line:
                    continue # skip blank lines

                timestamp, username, ip_address, status = clean_line.split()
                total_attempts += 1

                if status.upper() == "FAILED":
                    failed_count += 1
                    print(f"[WARNING] Failed login for {username} from {ip_address} at {timestamp}")
                elif status.upper() == "LOCKED":
                    locked_count += 1
                    print(f"[CRITICAL] Account locked for {username} from {ip_address} at {timestamp}")

    except FileNotFoundError:
        print("Error: Could not find the log file '{filename}'. Check your working directory.")
        return None

    return total_attempts, failed_count, locked_count


def calculate_failure_rate(failed, total) -> float:
    """
    @brief Calculates the percentage of failed login attempts
    :param failed: Number of failed login attempts
    :param total: Total number of login attempts
    :return: failure percentage as float
    """
    if total == 0:
        return 0.0
    return (failed / total) * 100

def write_report(filename, total, failed, locked, failed_rate):
    """
    @brief Writes a formatted security report summary to an output file
    :param filename: Path to the output file
    :param total: Total number of login attempts
    :param failed: Total number of failed login attempts
    :param locked: Total number of locked login attempts
    :param failed_rate: Calculated percentage of failed login attempts
    """
    with(open(filename, "w", encoding="utf-8")) as out_file:
        out_file.write("=======================================\n")
        out_file.write("     SERVER SECURITY AUDIT REPORT\n")
        out_file.write(" =======================================\n")
        out_file.write(f"Total Login Attempts : {total}\n")
        out_file.write(f"Failed Attempts      : {failed}\n")
        out_file.write(f"Accounts Locked      : {locked}\n")
        out_file.write(f"Failure Rate         : {failed_rate}%\n")
        out_file.write(" =======================================\n")

def main():
    """
    @brief Coordinates log analysis and report generation
    """

    input_file = "log_analyzer.txt"
    output_file = "security_report.txt"

    results = analyze_logs(input_file)
    if results is None:
        return

    total_attempts, failed_count, locked_count = results
    fail_rate = calculate_failure_rate(failed_count, total_attempts)
    write_report(output_file, total_attempts, failed_count, locked_count, fail_rate)
    print(f"\nAnalysis complete, Report written to {output_file}.")

if __name__ == "__main__":
    main()
