import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Replace 'your_capture.pcap' with the path to your PCAP file
pcap_file = 'capo.pcap'

# Function to process and print packet details
def process_packet(packet):
    global data  # Declare 'data' as a global variable

    # Access packet attributes like source IP, destination IP, protocol, etc.
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        # Print packet information
        print(f"Timestamp: {timestamp}")
        print(f"Source IP: {src_ip}, Source Port: {src_port}")
        print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
        print(f"Protocol: {protocol}\n")

        # Store packet information in a list (synchronized access)
        data.append([timestamp, src_ip, src_port, dst_ip, dst_port, protocol])

    except AttributeError:
        # Handle packets that do not contain necessary attributes
        print("Attribute error in packet:", packet)
        pass

# Initialize a list to store packet information
data = []

def main():
    global data  # Declare 'data' as a global variable

    # Open the PCAP file for reading
    cap = pyshark.FileCapture(pcap_file)

    # Process and print information for each packet in the PCAP file
    for packet in cap:
        process_packet(packet)

    # Close the PCAP file when finished
    cap.close()

if __name__ == "__main__":
    # Run the main function (synchronously)
    main()

    # Create a DataFrame for EDA
    df = pd.DataFrame(data, columns=['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol'])

    # Packet Loss Calculation
    total_packets = len(df)
    expected_packet_numbers = range(1, total_packets + 1)
    received_packet_numbers = df.index + 1
    packet_loss = total_packets - len(received_packet_numbers)

    print(f"Total Packets: {total_packets}")
    print(f"Received Packets: {len(received_packet_numbers)}")
    print(f"Packet Loss: {packet_loss}")

    # EDA: Pie chart of protocols
    protocol_counts = df['Protocol'].value_counts()
    plt.figure(figsize=(8, 8))
    plt.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', startangle=140)
    plt.title('Distribution of Protocols')
    plt.axis('equal')
    plt.show()
    
    # Encode categorical variables (Protocol)
    dff = df.copy()
    label_encoder = LabelEncoder()
    dff['Protocol'] = label_encoder.fit_transform(dff['Protocol'])

    # Define features (X) and target (y)
    X = dff[['Source Port', 'Destination Port', 'Protocol']]
    y = dff['Protocol']

    # Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train different classifiers
    classifiers = {
        'Random Forest': RandomForestClassifier(),
        'Decision Tree': DecisionTreeClassifier(),
        'Support Vector': SVC(),
        'k-Nearest Neighbors': KNeighborsClassifier(),
        'Naive Bayes': GaussianNB()
    }

    for clf_name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        
        # Decode the predicted labels
        y_pred_decoded = label_encoder.inverse_transform(y_pred)
        y_test_decoded = label_encoder.inverse_transform(y_test)
        
        # Generate a confusion matrix
        conf_matrix = confusion_matrix(y_test_decoded, y_pred_decoded)
        
        # Print a classification report
        classification_rep = classification_report(y_test_decoded, y_pred_decoded)
        
        print(f"Classifier: {clf_name}")
        print("Confusion Matrix:")
        print(conf_matrix)
        print("Classification Report:")
        print(classification_rep)
        print("\n")
