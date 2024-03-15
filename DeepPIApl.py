import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense
from decimal import Decimal
import matplotlib.pyplot as plt
from scapy.all import *
import os

# Function to calculate features from packets
def calculate_features(packets):
    # Initialize lists to store calculated features for forward and reverse directions
    forward_lengths = []
    reverse_lengths = []
    forward_intervals = []
    reverse_intervals = []
    forward_packet_rates = []
    reverse_packet_rates = []
    forward_byte_rates = []
    reverse_byte_rates = []
    features = []
    prev_time = None

    # Iterate over each packet in the pcap file
    for packet in packets:
        if packet.haslayer(IP):
            length = len(packet)
            time = packet.time
            protocol = packet[IP].proto
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Determine the direction based on source and destination IP addresses
            if src_ip == '192.168.0.193' and dst_ip != '192.168.0.193':
                forward_lengths.append(length)
            else:
                reverse_lengths.append(length)

            # Calculate inter-arrival time (piat) and rates
            if prev_time is not None:
                interval = time - prev_time
                if interval != 0:
                    if src_ip == '192.168.0.193' and dst_ip != '192.168.0.193':
                        forward_intervals.append(interval)
                        forward_packet_rates.append(1 / interval)
                        forward_byte_rates.append(length / interval)  # Calculate byte rate
                    else:
                        reverse_intervals.append(interval)
                        reverse_packet_rates.append(1 / interval)
                        reverse_byte_rates.append(length / interval)

            # Update prev_time for the next iteration
            prev_time = time

    # Calculate statistics for forward and reverse features
            forward_pl_mean = np.mean(forward_lengths) if forward_lengths else 0
            forward_pl_var = np.var(forward_lengths) if forward_lengths else 0
            forward_pl_q1 = np.percentile(forward_lengths, 25) if forward_lengths else 0
            forward_pl_q3 = np.percentile(forward_lengths, 75) if forward_lengths else 0
            forward_pl_max = np.max(forward_lengths) if forward_lengths else 0
            forward_pl_min = np.min(forward_lengths) if forward_lengths else 0
            forward_piat_mean = np.mean([float(val) for val in forward_intervals]) if forward_intervals else 0
            forward_piat_var = np.var([float(val) for val in forward_intervals]) if forward_intervals else 0
            forward_piat_q1 = np.percentile([float(val) for val in forward_intervals], 25) if forward_intervals else 0
            forward_piat_q3 = np.percentile([float(val) for val in forward_intervals], 75) if forward_intervals else 0
            forward_pps_mean = np.mean(forward_packet_rates) if forward_packet_rates else 0
            forward_pps_var = np.var(forward_packet_rates) if forward_packet_rates else 0
            forward_pps_max = np.max(forward_packet_rates) if forward_packet_rates else 0
            forward_pps_min = np.min(forward_packet_rates) if forward_packet_rates else 0
            forward_bps_mean = np.mean(forward_byte_rates) if forward_byte_rates else 0
            forward_bps_var = np.var(forward_byte_rates) if forward_byte_rates else 0
            forward_bps_max = np.max(forward_byte_rates) if forward_byte_rates else 0
            forward_bps_min = np.min(forward_byte_rates) if forward_byte_rates else 0
            forward_piat_max = np.max(forward_intervals) if forward_intervals else 0
            forward_piat_min = np.min(forward_intervals) if forward_intervals else 0

            reverse_pl_mean = np.mean(reverse_lengths) if reverse_lengths else 0
            reverse_pl_var = np.var(reverse_lengths) if reverse_lengths else 0
            reverse_pl_q1 = np.percentile(reverse_lengths, 25) if reverse_lengths else 0
            reverse_pl_q3 = np.percentile(reverse_lengths, 75) if reverse_lengths else 0
            reverse_pl_max = np.max(reverse_lengths) if reverse_lengths else 0
            reverse_pl_min = np.min(reverse_lengths) if reverse_lengths else 0
            reverse_piat_mean = np.mean([float(val) for val in reverse_intervals]) if reverse_intervals else 0
            reverse_piat_var = np.var([float(val) for val in reverse_intervals]) if reverse_intervals else 0
            reverse_piat_q1 = np.percentile([float(val) for val in reverse_intervals], 25) if reverse_intervals else 0
            reverse_piat_q3 = np.percentile([float(val) for val in reverse_intervals], 75) if reverse_intervals else 0
            reverse_pps_mean = np.mean(reverse_packet_rates) if reverse_packet_rates else 0
            reverse_pps_var = np.var(reverse_packet_rates) if reverse_packet_rates else 0
            reverse_pps_max = np.max(reverse_packet_rates) if reverse_packet_rates else 0
            reverse_pps_min = np.min(reverse_packet_rates) if reverse_packet_rates else 0
            reverse_bps_mean = np.mean(reverse_byte_rates) if reverse_byte_rates else 0
            reverse_bps_var = np.var(reverse_byte_rates) if reverse_byte_rates else 0
            reverse_bps_max = np.max(reverse_byte_rates) if reverse_byte_rates else 0
            reverse_bps_min = np.min(reverse_byte_rates) if reverse_byte_rates else 0
            reverse_piat_max = np.max(reverse_intervals) if reverse_intervals else 0
            reverse_piat_min = np.min(reverse_intervals) if reverse_intervals else 0

            # Append forward and reverse features into the features list
            features.append([
                forward_pl_mean, forward_pl_var, forward_pl_q1, forward_pl_q3, forward_pl_max, forward_pl_min,
                forward_piat_mean, forward_piat_var, forward_piat_q1, forward_piat_q3,
                forward_pps_mean, forward_pps_var, forward_pps_max, forward_pps_min,
                forward_bps_mean, forward_bps_var, forward_bps_max, forward_bps_min,
                forward_piat_max, forward_piat_min,  
                reverse_pl_mean, reverse_pl_var, reverse_pl_q1, reverse_pl_q3, reverse_pl_max, reverse_pl_min,
                reverse_piat_mean, reverse_piat_var, reverse_piat_q1, reverse_piat_q3,
                reverse_pps_mean, reverse_pps_var, reverse_pps_max, reverse_pps_min,
                reverse_bps_mean, reverse_bps_var, reverse_bps_max, reverse_bps_min,
                reverse_piat_max, reverse_piat_min 
            ])

    # Print or use the list of features as needed
    features = np.array(features, dtype=np.float64)

    features = np.array([float(x) if isinstance(x, Decimal) else x for x in features])

    # # Set printing options to display all elements without scientific notation
    np.set_printoptions(threshold=np.inf, suppress=True)

    print(features)
    print("Shape of features:", features.shape)

    return features

# Load SDN dataset
sdn_dataset = pd.read_csv('sdn_dataset.csv', sep=";", low_memory=True)
# Handle missing values if any
sdn_dataset.dropna(inplace=True)

# Prepare features and labels
X = sdn_dataset.drop(columns=['category'])  # Features
y = sdn_dataset['category']  # Labels

# Encode categorical labels
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Normalize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Reshape features for CNN input
X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

# Define a simple CNN model
model = Sequential()
model.add(Conv1D(32, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], X_train.shape[2])))
model.add(MaxPooling1D(pool_size=2))
model.add(Conv1D(64, kernel_size=3, activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(Flatten())
model.add(Dense(256, activation='relu'))
model.add(Dense(len(label_encoder.classes_), activation='softmax'))

# Compile the model
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))

# Evaluate the model
test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f'Test Accuracy: {test_accuracy}')
print(f'Test Loss: {test_loss}')

# Generate predictions
y_pred = model.predict(X_test)
y_pred_classes = np.argmax(y_pred, axis=1)

# Generate classification report and confusion matrix
print(classification_report(y_test, y_pred_classes, target_names=label_encoder.classes_))
conf_matrix = confusion_matrix(y_test, y_pred_classes)
print('Confusion Matrix:')
print(conf_matrix)

# Load pcap file
pcap_file = 'capo.pcap'
if os.path.exists(pcap_file):
    # Read pcap file
    packets = rdpcap(pcap_file)

    # Calculate features
    features = calculate_features(packets)
    
    # Display all 40 features for the first packet
    # print("Features for the first packet:")
    # for i, feature_value in enumerate(features[0]):
    #     print(f"Feature {i+1}: {feature_value}")

    # Normalize the features
    features_normalized = scaler.transform(features)

    # Reshape features for CNN input
    features_reshaped = features_normalized.reshape(features_normalized.shape[0], features_normalized.shape[1], 1)
    
    # # Predict application protocol for single 1st packet 
    # y_pcap_pred = model.predict(features_reshaped)
    # y_pcap_pred_classes = np.argmax(y_pcap_pred, axis=1)
    
    # # Convert predicted classes to protocol names
    # predicted_protocol = label_encoder.inverse_transform(y_pcap_pred_classes)
    
    # # Display predicted application protocol
    # print("Predicted Application Protocol for pcap file:", predicted_protocol[0])
    
        
    # Predict application protocols for the entire packets in pcap file
    y_pcap_pred = model.predict(features_reshaped)
    y_pcap_pred_classes = np.argmax(y_pcap_pred, axis=1)

    # Convert predicted classes to protocol names
    predicted_protocols = label_encoder.inverse_transform(y_pcap_pred_classes)
        
    # Display predicted application protocols for each packet
    for i, protocol in enumerate(predicted_protocols):
        print(f"Packet {i + 1}: {protocol}")
        
    # Count the occurrences of each predicted protocol
    unique_protocols, protocol_counts = np.unique(predicted_protocols, return_counts=True)

    # Create a pie chart with better formatting
    plt.figure(figsize=(8, 8))
    patches, texts, _ = plt.pie(protocol_counts, labels=unique_protocols, autopct='%1.6f%%', startangle=140)
    
    # Improve label formatting
    for text in texts:
        text.set_fontsize(14)  # Set font size
        text.set_horizontalalignment('center')  # Center align labels

    plt.title('Distribution of Predicted Application Protocols', fontsize=14)  # Set title and font size
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.tight_layout()  
    plt.legend()
    plt.show()
    
else:
    print(f"The file {pcap_file} does not exist.")