from natsort import natsorted, ns
import numpy as np
import pandas as pd
import os
import shutil
import tempfile
import optparse


class Patch:
    def __init__(self):
        self.df = pd.DataFrame()
        os.chdir(tempfile.gettempdir())
        if "CSV" not in os.listdir(tempfile.gettempdir()):
            os.mkdir("CSV")

    def csv_finder(self, movdir, basedir):
        for root, dirs, files in os.walk(movdir):
            for filename in files:
                if filename.endswith('.csv'):
                    old_name = os.path.join(os.path.abspath(root), filename)
                    temp = pd.read_csv(old_name)
                    ip = temp['Host'][0]
                    base, extension = os.path.splitext(filename)
                    new_name = os.path.join(basedir, ip + extension)
                    shutil.copy(old_name, new_name)

    def csv_list(self, basedir):
        nm = np.array([])
        for dirName, subdirList, fileList in os.walk(basedir):
            for fname in sorted(fileList):
                nm = np.append(nm, fname)
        return natsorted(nm, alg=ns.IGNORECASE)

    def csv_out(self, basedir, nm):
        count = 0
        for str in nm:
            count += 1
            nessus_data = pd.read_csv(basedir + "/" + str)
            nessus_data = pd.DataFrame(nessus_data, columns=['Plugin ID', 'Host', 'Name', 'Description', 'Solution',
                                                             'See Also', 'Plugin Output', 'Risk'])
            nessus_data.drop_duplicates(subset="Name", keep='first', inplace=True)
            nessus_data.drop(nessus_data[nessus_data['Risk'] == 'None'].index, inplace=True)
            nessus_data = nessus_data.sort_values(by=['Risk'])
            nessus_data = nessus_data.reset_index()
            # print(nessus_data['Host'][1])
            if self.df.empty:
                self.df = nessus_data
            else:
                for i, rowi in nessus_data.iterrows():
                    for j, rowj in self.df.iterrows():
                        if rowi['Name'] == rowj['Name']:
                            prv_ip = rowj['Host']
                            ip = rowi['Host']
                            new_ip = prv_ip + ", " + ip
                            self.df.at[j, 'Host'] = new_ip
                            break
                    if len(self.df.index) == j+1:
                        self.df = self.df.append(rowi, ignore_index=True)

    # def remove_patch(self, local_nessus_data):
    #     num = np.array([])
    #     for ind, row in local_nessus_data.iterrows():
    #         name = row['Name']
    #         pat = name[:2]
    #         if pat == "MS" or pat == "KB":
    #             np.append(num, ind)
    #     local_nessus_data = local_nessus_data.drop(num)
    #     print(local_nessus_data)
    #     return local_nessus_data

    def to_text(self, movdir):
        csv_file = movdir + "\\summaryCSV.csv"
        csv_df = pd.read_csv(csv_file)
        with open(movdir + "\\_vuln_.txt", "w") as f:
            for ind, row in csv_df.iterrows():
                name = row['Name']
                if name[:4] == "RHEL":
                    continue
                # print(str(ind+1)+")" + name)
                description = row['Description']
                plugin_id = row['Plugin ID']
                # print("Description:\n" + description + "\n")
                affected_devices = row['Host']
                # print("Affected Devices:\n" + affected_devices + "\n")
                risk_level = row['Risk']
                # print("Risk Level:\n" + risk_level + "\n")
                recommendation = row['Solution']
                plugin_out = str(row['Plugin Output'])
                if not plugin_out == "nan":
                    recommendation = recommendation + "\n" + plugin_out
                # print("Recommendation:\n" + recommendation + "\n")
                see_also = str(row['See Also']).encode('utf-8')
                # print("See Also:\n" + see_also + "\n")

                print ("\n\n\n")
                f.write(str(ind+1)+")" + name + "\n")
                f.write(name + "\n")
                # f.write("Description:\n" + description + "\n\n")
                # f.write("Affected Devices:\n" + affected_devices + "\n\n")
                # f.write("Risk Level:\n" + risk_level + "\n\n")
                f.write("Recommendation:\n" + recommendation + "\n\n")
                # if not see_also == "nan":
                #     f.write("See Also:\n" + see_also + "\n\n")
                # else:
                #     f.write("See Also:\n" + "https://www.tenable.com/plugins/nessus/" + str(plugin_id) + "\n\n")
                # f.write("\n\n\n")

    def find_patches(self, movdir):
        os.chdir(tempfile.gettempdir() + "/CSV")
        basedir = os.getcwd()
        self.csv_finder(movdir, basedir)
        # operating_sys = movdir.split("\\")[-1]
        nm = self.csv_list(basedir)
        self.csv_out(basedir, nm)
        self.df = self.df.sort_values(by=['Risk'])
        self.df = self.df.reset_index()
        self.df.to_csv(movdir + "\\summaryCSV.csv")
        # self.to_text()
        # print("[+] Generating patch.txt and ip.txt For " + operating_sys)
        for file in os.listdir(basedir):
            os.remove(file)


parse = optparse.OptionParser()
parse.add_option("-t", "--target", dest="target", help="Enter the path of the target folder")
# parse.add_option("-o", "--output", dest="output",help="Convert to Text file")
(options, arguments) = parse.parse_args()
if options.target:
    movdir = options.target
    obj = Patch()
    obj.find_patches(movdir)
    # obj.to_text(movdir)

# if options.output:
#     movdir = options.output
#     obj = Patch()
#     obj.to_text(movdir)
