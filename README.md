# 113-1 Introduction to Emerging Memory Techniques

This repository contains the lab projects and assignments completed for the 113-1 Introduction to Emerging Memory Techniques course. The labs focus on hands-on exploration of SSD firmware development, SCSI command integration, and advanced memory techniques, providing practical insights into emerging storage technologies.

## Labs Overview

### Lab 1: Hands-on SSD

- Objective: Setup the environment for firmware development, initialize SSDs, and implement UART communication.
- Tasks:
  - Modify SSD firmware to enable data read/write operations across complete blocks.
  - Implement custom UART commands to display information and execute operations.
  - Debug and deploy firmware updates via VirtualBox and MPTool.

### Lab 2: SCSI Command Implementation

- Objective: Develop and test SCSI commands for SSD data operations.
- Tasks:
  - Implement READ (16) and WRITE (16) SCSI commands to manage SSD block operations.
  - Create a command-line tool to parse arguments and execute SCSI commands.
  - Perform performance analysis of data transfers and validate SSD behavior.

### Lab 3: Write Protection Mechanism

- Objective: Integrate write protection features into SSD firmware.
- Tasks:
  - Implement protectEnable and protectDisable commands via UART.
  - Ensure data integrity by restricting write operations when protection is enabled.
  - Demonstrate functionality with real-time debugging and validation through SCSI commands.
