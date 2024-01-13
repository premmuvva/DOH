import pandas as pd
import numpy as np

# Assuming new_df is your 2D DataFrame
# Example DataFrame creation for illustration purposes
data = {'column1': [1, 2, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 6, 7, np.nan, np.nan, 10, np.nan, np.nan, np.nan, np.nan, np.nan],
        'column2': [11, 12, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 16, 17, np.nan, np.nan, 110, np.nan, np.nan, np.nan, np.nan, np.nan]}
new_df = pd.DataFrame(data)

# Set the threshold for subsequent NaN values
nan_threshold = 5

# Create a mask to identify rows where 20 subsequent rows have NaN values
# nan_mask = new_df.apply(lambda row: row.rolling(window=nan_threshold).sum(), axis=1) == nan_threshold

print("iloc", new_df.iloc[1:4])
# Iterate through the DataFrame and skip rows where the next nan_threshold subsequent rows all have NaN values
final_rows = []
flag = True
for i in range(len(new_df)):
    final_rows.append(new_df.iloc[i:i+nan_threshold].reset_index(drop=True))
    if i + nan_threshold <= len(new_df) and new_df.iloc[i:i+nan_threshold].isna().all().all():
        if flag:
            flag = False
            i += (nan_threshold + 1)
            continue
        flag = True
        break
    i += (nan_threshold + 1)
     
flag = True

print("final_rows")
print(final_rows)

for i in range(0, len(new_df)):
    final_rows.append(new_df.iloc[i:i+nan_threshold])
    if i + nan_threshold <= len(new_df) and new_df.iloc[i:i+nan_threshold].isna().all().all():
        if flag:
            flag = False
            i += (nan_threshold + 1)
            continue
        flag = True
        break
    i += (nan_threshold + 1)

print("final_rows")
print(final_rows)

# Create the final DataFrame
final_df = pd.DataFrame(final_rows)


# print("mask", nan_mask)
# # Apply the mask to exclude rows
# final_df = new_df[~nan_mask]

print("Original DataFrame:", len(new_df))
print(new_df)
print("\nFinal DataFrame:", len(final_df))
print(final_df)