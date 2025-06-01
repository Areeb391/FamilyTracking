let map = L.map('map').setView([0, 0], 2);  // Initial zoomed-out view



L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {

    attribution: '&copy; OpenStreetMap contributors'

}).addTo(map);



let marker = L.marker([0, 0]).addTo(map);



// Fetch and update location every 3 seconds

function updateLocation() {

    fetch('/get_location')

        .then(res => res.json())

        .then(data => {

            marker.setLatLng([data.lat, data.lng]);

            map.setView([data.lat, data.lng], 15);

        });

}



setInterval(updateLocation, 3000);