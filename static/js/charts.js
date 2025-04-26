/**
 * Charts utility functions for IoT Network Traffic Analyzer
 */

// Function to create a protocol distribution pie chart
function createProtocolChart(elementId, protocolData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    if (!protocolData || Object.keys(protocolData).length === 0) {
        showNoDataMessage(ctx, 'No protocol data available');
        return;
    }
    
    const labels = Object.keys(protocolData);
    const values = Object.values(protocolData);
    
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Function to create a port distribution bar chart
function createPortChart(elementId, portData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    if (!portData || Object.keys(portData).length === 0) {
        showNoDataMessage(ctx, 'No port data available');
        return;
    }
    
    const labels = Object.keys(portData);
    const values = Object.values(portData);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packet Count',
                data: values,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Function to create a traffic over time line chart
function createTimeChart(elementId, timeData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    if (!timeData || Object.keys(timeData).length === 0) {
        showNoDataMessage(ctx, 'No time distribution data available');
        return;
    }
    
    const labels = Object.keys(timeData);
    const values = Object.values(timeData);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packet Count',
                data: values,
                fill: true,
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Function to create an anomaly score distribution chart
function createAnomalyScoreChart(elementId, anomalyData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    if (!anomalyData || anomalyData.length === 0) {
        showNoDataMessage(ctx, 'No anomaly data available');
        return;
    }
    
    // Extract scores and organize them into bins
    const scores = anomalyData.map(a => Math.abs(a.anomaly_score));
    const bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0];
    const binCounts = Array(bins.length - 1).fill(0);
    
    scores.forEach(score => {
        for (let i = 0; i < bins.length - 1; i++) {
            if (score >= bins[i] && score < bins[i + 1]) {
                binCounts[i]++;
                break;
            }
        }
    });
    
    const binLabels = bins.slice(0, -1).map((bin, i) => `${bin.toFixed(1)}-${bins[i+1].toFixed(1)}`);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: binLabels,
            datasets: [{
                label: 'Number of Anomalies',
                data: binCounts,
                backgroundColor: 'rgba(255, 99, 132, 0.7)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Count'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Anomaly Score Range'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: function(tooltipItems) {
                            return `Score Range: ${tooltipItems[0].label}`;
                        }
                    }
                }
            }
        }
    });
}

// Helper function to show "no data" message in place of a chart
function showNoDataMessage(ctx, message) {
    ctx.canvas.style.display = 'none';
    const noDataMsg = document.createElement('div');
    noDataMsg.className = 'text-center py-5';
    noDataMsg.innerHTML = `<i class="fas fa-chart-bar fa-3x mb-3 text-muted"></i><p>${message}</p>`;
    ctx.canvas.parentNode.appendChild(noDataMsg);
}

// Function to create a dashboard summary chart with dynamic data
function createDashboardChart(elementId, scanData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // Generate dates for the last 7 days
    const labels = [];
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString());
    }
    
    // If no real data is available, use minimal placeholder data
    const packetData = scanData && scanData.length > 0 ? 
        scanData.map(s => s.total_packets) : 
        [0, 0, 0, 0, 0, 0, 0];
    
    const anomalyData = scanData && scanData.length > 0 ? 
        scanData.map(s => s.anomalies_detected) : 
        [0, 0, 0, 0, 0, 0, 0];
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Packets Analyzed',
                    data: packetData,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Anomalies Detected',
                    data: anomalyData,
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}
