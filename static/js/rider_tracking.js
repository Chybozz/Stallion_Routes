function initTracking(pickupAddress, deliveryAddress) {
    const map = L.map('map').setView([6.3249, 8.1137], 13);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '© OpenStreetMap contributors'
    }).addTo(map);

    async function geocode(address) {
        const res = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}`);
        const data = await res.json();
        if (data && data.length) {
            return [parseFloat(data[0].lat), parseFloat(data[0].lon)];
        }
        throw new Error(`Geocode failed for: ${address}`);
    }

    function animateMarker(marker, path, speed = 100) {
        let index = 0;
        const interval = setInterval(() => {
            if (index >= path.length) {
                clearInterval(interval);
                return;
            }
            marker.setLatLng(path[index]);
            map.panTo(path[index]);
            index++;
        }, speed);
    }

    async function simulate() {
        try {
            const pickupLatLng = await geocode(pickupAddress);
            const deliveryLatLng = await geocode(deliveryAddress);

            // Marker: Pickup & Delivery
            L.marker(pickupLatLng).addTo(map).bindPopup("📦 Pickup Location").openPopup();
            L.marker(deliveryLatLng).addTo(map).bindPopup("🏁 Delivery Location");

            // Simulate Rider starting 500m behind pickup
            const startLatLng = [
                pickupLatLng[0] - 0.005,
                pickupLatLng[1] - 0.005
            ];

            const riderIcon = L.icon({
                iconUrl: 'https://cdn-icons-png.flaticon.com/512/2554/2554972.png',
                iconSize: [40, 40],
                iconAnchor: [20, 20]
            });

            const riderMarker = L.marker(startLatLng, { icon: riderIcon }).addTo(map);

            // Step 1: Move to pickup
            const toPickup = await getRoute(startLatLng, pickupLatLng);
            animateMarker(riderMarker, toPickup, 80);

            setTimeout(async () => {
                // Step 2: Move to delivery
                const toDelivery = await getRoute(pickupLatLng, deliveryLatLng);
                animateMarker(riderMarker, toDelivery, 80);
            }, toPickup.length * 80 + 500); // Wait until pickup is reached

        } catch (err) {
            console.error("Simulation failed:", err);
        }
    }

    async function getRoute(from, to) {
        return new Promise((resolve, reject) => {
            L.Routing.control({
                waypoints: [L.latLng(from), L.latLng(to)],
                createMarker: () => null,
                router: new L.Routing.osrmv1({
                    serviceUrl: 'https://router.project-osrm.org/route/v1'
                }),
                addWaypoints: false,
                fitSelectedRoutes: false,
                routeWhileDragging: false
            }).on('routesfound', function (e) {
                const coordinates = e.routes[0].coordinates;
                resolve(coordinates);
            }).on('routingerror', reject).addTo(map);
        });
    }

    simulate();
}