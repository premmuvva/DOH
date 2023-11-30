import os
import numpy as np

def merge_npy_files_in_directory(directory_path, output_path):
    # Get a list of all .npy files in the specified directory
    npy_files = [f for f in os.listdir(directory_path) if f.endswith('.npy')]
    # print()
    if not npy_files:
        print("No .npy files found in the specified directory.")
        return
    # print(npy_files)
    # Load the first .npy file to initialize the merged_data
    merged_data = np.load(os.path.join(directory_path, npy_files[0]), allow_pickle=True)
    # print(len(merged_data))

    # Iterate over the remaining .npy files and concatenate their data
    for npy_file in npy_files[1:]:
        data = np.load(os.path.join(directory_path, npy_file), allow_pickle=True)
        print(f"merging file : {npy_file} of length {len(data)}")
        merged_data = np.concatenate((merged_data, data), axis=0)

    print("final merge size", len(merged_data))
    # Save the merged data to a new .npy file
    np.save(output_path, merged_data)
    print(f"Merged data saved to {output_path}.")

# Example usage:
directory_path = 'output/3/'
output_path = 'output/11/begign.npy'

merge_npy_files_in_directory(directory_path, output_path)


# def find_missing_files(directory_path, base_filename, total_files):
#     existing_files = set()
#     missing_files = []

#     # Get a list of all files in the specified directory
#     all_files = os.listdir(directory_path)

#     # Extract the numeric part of the filename and add it to the existing_files set
#     for filename in all_files:
#         if filename.startswith(base_filename) and filename.endswith('.npy'):
#             try:
#                 file_number = int(filename[len(base_filename):-len('.npy')])
#                 existing_files.add(file_number)
#             except ValueError:
#                 pass  # Ignore files that do not match the expected pattern
    
#         # Find missing files in the range
#     for i in range(1, total_files + 1):
#         if i not in existing_files:
#             missing_files.append(f"{base_filename}{i}.npy")

#     # return missing_files
#     print(missing_files)

# base_filename = 'df'
# total_files = 1046

# missing_files = find_missing_files(directory_path, base_filename, total_files)
