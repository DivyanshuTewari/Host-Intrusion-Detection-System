document.addEventListener('DOMContentLoaded', () => {
    const statusText = document.getElementById('status-text');
    const pathsText = document.getElementById('paths-text');
    const activitiesList = document.getElementById('activities-list');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const clearBtn = document.getElementById('clear-btn');

    let previousActivities = [];

function updateStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            statusText.textContent = `Monitoring: ${data.monitoring ? 'Active' : 'Stopped'}`;
            pathsText.textContent = data.paths;
            startBtn.disabled = data.monitoring;
            stopBtn.disabled = !data.monitoring;

            const alertSound = document.getElementById('alert-sound');

            // Detect new activity
            const newActivities = data.activities.filter(
                act => !previousActivities.some(prev => prev.timestamp === act.timestamp && prev.message === act.message)
            );

            // Update list
            activitiesList.innerHTML = '';
            data.activities.forEach(activity => {
                const li = document.createElement('li');
                li.textContent = `[${activity.timestamp}] ${activity.message}`;
                activitiesList.appendChild(li);
            });

            if (newActivities.length > 0 && alertSound) {
                alertSound.play();
            }

            previousActivities = data.activities;
        })
        .catch(error => console.error('Error fetching status:', error));
}


    // Initial update and polling
    updateStatus();
    setInterval(updateStatus, 5000);

    // Button event listeners
    startBtn.addEventListener('click', () => {
        fetch('/api/start', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                console.log(data.message);
                updateStatus();
            })
            .catch(error => console.error('Error starting monitoring:', error));
    });

    stopBtn.addEventListener('click', () => {
        fetch('/api/stop', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                console.log(data.message);
                updateStatus();
            })
            .catch(error => console.error('Error stopping monitoring:', error));
    });

    clearBtn.addEventListener('click', () => {
        fetch('/api/clear', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                updateStatus();
            })
            .catch(error => console.error('Error clearing log:', error));
    });
});