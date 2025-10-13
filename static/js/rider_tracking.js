let map, directionsService, directionsRenderer;
let pickupMarker, deliveryMarker, riderMarker;
let routePath = null;
let currentRiderPosition = null;

// Initialize Google Map
function initMap(pickupAddress, deliveryAddress) {
    document.getElementById("rider-location-map").style.display = "block";

    map = new google.maps.Map(document.getElementById("rider-map"), {
        zoom: 13,
        center: { lat: 6.3249, lng: 8.1137 } // default center (Abakaliki)
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
    ]).then(([pickupCoords, deliveryCoords]) => {
        addMarkers(pickupCoords, deliveryCoords);
        drawRoute(pickupCoords, deliveryCoords);
        calculateFare(pickupCoords, deliveryCoords);

        // Simulate rider movement for now
        simulateRider(pickupCoords, deliveryCoords);
    }).catch(err => console.error("Geocode Error:", err));
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
        title: "Delivery Destination"
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
            // You can also display this fare somewhere in your HTML
        }
    });
}

// Simulate rider moving along the route (for demo)
function simulateRider(start, end) {
    if (!routePath) return;

    let index = 0;

    riderMarker = new google.maps.Marker({
        position: start,
        map,
        title: "Rider",
        icon: {
            url: "https://maps.google.com/mapfiles/kml/shapes/motorcycling.png",
            scaledSize: new google.maps.Size(40, 40)
        }
    });

    const interval = setInterval(() => {
        if (index >= routePath.length) {
            clearInterval(interval);
            console.log("Rider reached destination!");
            return;
        }

        const nextPosition = routePath[index];
        riderMarker.setPosition(nextPosition);
        map.panTo(nextPosition);

        index++;
    }, 1000); // update every second
}