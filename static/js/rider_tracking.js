let map, directionsService, directionsRenderer;
let pickupMarker, deliveryMarker, riderMarker;
let routePath = [];

// Initialize Google Map
function initMap(pickupAddress, deliveryAddress) {
    document.getElementById("rider-location-map").style.display = "block";

    map = new google.maps.Map(document.getElementById("rider-map"), {
        zoom: 13,
        center: { lat: 6.3249, lng: 8.1137 } // default Abakaliki center
    });

    directionsService = new google.maps.DirectionsService();
    directionsRenderer = new google.maps.DirectionsRenderer({
        map,
        suppressMarkers: true
    });

    const geocoder = new google.maps.Geocoder();

    Promise.all([
        geocodeAddress(geocoder, pickupAddress),
        geocodeAddress(geocoder, deliveryAddress)
    ])
    .then(([pickupCoords, deliveryCoords]) => {
        addMarkers(pickupCoords, deliveryCoords);
        drawRoute(pickupCoords, deliveryCoords);
        calculateFare(pickupCoords, deliveryCoords);
    })
    .catch(err => console.error("Geocode Error:", err));
}

// Convert address to coordinates
function geocodeAddress(geocoder, address) {
    return new Promise((resolve, reject) => {
        geocoder.geocode({ address }, (results, status) => {
            if (status === "OK") {
                resolve(results[0].geometry.location);
            } else {
                reject("Geocode failed: " + status);
            }
        });
    });
}

// Add pickup and delivery markers
function addMarkers(pickup, delivery) {
    pickupMarker = new google.maps.Marker({
        position: pickup,
        map,
        label: "P",
        title: "Pickup Location"
    });

    deliveryMarker = new google.maps.Marker({
        position: delivery,
        map,
        label: "D",
        title: "Delivery Location"
    });

    map.setCenter(pickup);
}

// Draw route between pickup and delivery
function drawRoute(start, end) {
    const request = {
        origin: start,
        destination: end,
        travelMode: google.maps.TravelMode.DRIVING
    };

    directionsService.route(request, (result, status) => {
        if (status === "OK") {
            directionsRenderer.setDirections(result);
            routePath = result.routes[0].overview_path;
            simulateRider(routePath); // Start simulated rider once route loads
        } else {
            console.error("Directions request failed:", status);
        }
    });
}

// Calculate distance and estimated fare
function calculateFare(start, end) {
    const service = new google.maps.DistanceMatrixService();
    service.getDistanceMatrix({
        origins: [start],
        destinations: [end],
        travelMode: google.maps.TravelMode.DRIVING
    }, (response, status) => {
        if (status === "OK") {
            const element = response.rows[0].elements[0];
            const distanceKm = element.distance.value / 1000;
            const fare = Math.max(500, distanceKm * 150); // ₦150/km, min ₦500
            console.log(`Distance: ${element.distance.text}, Fare: ₦${fare.toFixed(0)}`);
        } else {
            console.error("Distance calculation failed:", status);
        }
    });
}

// Simulate rider moving along the route
function simulateRider(route) {
    if (!route || route.length === 0) return;

    let index = 0;

    riderMarker = new google.maps.Marker({
        position: route[0],
        map,
        title: "Rider",
        icon: {
            url: "https://maps.google.com/mapfiles/kml/shapes/motorcycling.png",
            scaledSize: new google.maps.Size(40, 40)
        }
    });

    const interval = setInterval(() => {
        if (index >= route.length) {
            clearInterval(interval);
            console.log("✅ Rider reached destination!");
            return;
        }

        const nextPosition = route[index];
        riderMarker.setPosition(nextPosition);
        map.panTo(nextPosition);
        index++;
    }, 1000);
}
