let map = L.map('map').setView([0, 0], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

let marker = L.marker([0, 0]).addTo(map);

function sendLocation(lat, lng) {
    fetch('/update_location', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ lat: lat, lng: lng })
    });
}

function updateLocation() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(position => {
            const lat = position.coords.latitude;
            const lng = position.coords.longitude;
            map.setView([lat, lng], 15);
            marker.setLatLng([lat, lng]);
            sendLocation(lat, lng);
        }, () => {
            console.error("Permission denied or location unavailable.");
        });
    } else {
        console.error("Geolocation is not supported by this browser.");
    }
}

setInterval(updateLocation, 5000);
