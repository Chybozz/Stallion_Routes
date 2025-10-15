if (window.location.pathname.includes('rider_dashboard')) {
    document.addEventListener('DOMContentLoaded', function () {
        function updateTime() {
            var now = new Date(); // Get current time
            var current_time = now.toLocaleTimeString(); // Format time as HH:MM:SS
            var time_display = document.getElementById('time-display');
            time_display.innerHTML = current_time; // Update the HTML element

            let time_greeting = now;
            let hours = time_greeting.getHours();

            if (hours >= 17) {  // 5:00 PM and later
                document.getElementById('greeting').innerHTML = 'Good Evening';
            } else if (hours >= 12) {  // 12:00 PM to 4:59 PM
                document.getElementById('greeting').innerHTML = 'Good Afternoon';
            } else {  // Before 12:00 PM
                document.getElementById('greeting').innerHTML = 'Good Morning';
            }
        }
        // Call the updateTime function every second (1000 ms)
        setInterval(updateTime, 1000);

        // Run the updateTime function on page load to ensure it's immediately shown
        updateTime();

        // Toggle between the "New" and "Active" deliveries views
        var btn_new = document.getElementById('new-btn-deliveries');
        var btn_active = document.getElementById('active-btn-deliveries');

        // New Delivery Button
        btn_new.addEventListener('click', () => {
            if (btn_active.classList.contains('hidden')) {
                btn_active.classList.remove('hidden');
                btn_new.classList.add('hidden');
                location.reload();
            }
        });
        btn_active.addEventListener('click', () => {
            if (btn_new.classList.contains('hidden')) {
                btn_new.classList.remove('hidden');
                btn_active.classList.add('hidden');
                document.getElementById('active-deliveries').classList.remove('hidden'); // show
                document.getElementById('new-deliveries').classList.add('hidden'); // hidden
            }
        });

        // Handle the "Accept" and "Track" buttons for delivery requests
        document.querySelectorAll('.accept-btn, .track-btn').forEach(button => {
            button.addEventListener('click', function (event) {
                event.preventDefault(); // Prevent the default form submission

                const requestID = this.getAttribute('data-request-id');
                const actionValue = this.value;
                const riderId = document.getElementById('r-id').textContent;
                const riderName = document.getElementById('rider-name').textContent;
                const riderPhone = document.getElementById('rider-phone').textContent;
                const tranDate = document.getElementById('date').textContent;
                const tranTime = document.getElementById('time-display').textContent;

                // Prepare data to send
                const requestData = {
                    reqID: requestID,
                    action: actionValue,
                    rider_id: riderId,
                    rider_name: riderName,
                    rider_phone: riderPhone,
                    transaction_date: tranDate,
                    transaction_time: tranTime
                };

                // Send the data using fetch API
                fetch('/rider_dashboard', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest' // Mark as AJAX request
                    },
                    body: JSON.stringify(requestData)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update the page dynamically based on response
                        alert(data.message);
                        if (actionValue === 'accept') {
                            document.getElementById(`request-card-${requestID}`).remove();
                            location.reload();
                        }
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => console.error('Error:', error));
            });
        });

        // Handle the "Deliver" and "Track" buttons for delivery requests
        document.querySelectorAll('.deliver-btn, .tracks-btn').forEach(button => {
            button.addEventListener('click', function (event) {
                event.preventDefault(); // Prevent the default form submission

                const requestID = this.getAttribute('data-request-id');
                const pickupAddress = this.getAttribute('data-pickup'); // Assuming pickup and delivery addresses are set in the button
                const deliveryAddress = this.getAttribute('data-delivery');
                const actionValue = this.value;
                const riderId = document.getElementById('r-id').textContent;
                const tranTime = document.getElementById('time-display').textContent;

                // Prepare data to send
                const requestData = {
                    reqID: requestID,
                    action: actionValue,
                    rider_id: riderId,
                    transaction_time: tranTime
                };

                // Send the data using fetch API
                fetch('/deliver', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest' // Mark as AJAX request
                    },
                    body: JSON.stringify(requestData)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update the page dynamically based on response
                        alert(data.message);
                        if (actionValue === 'deliver') {
                            // document.getElementById(`request-card-${requestID}`).remove();
                            const card = document.getElementById(`request-card-${requestID}`);
                            const button = card.querySelector('button[data-request-id]'); // Find the button within the card
                            //button.classList.remove('btn-primary', 'deliver-btn');
                            button.remove();
                            const label = document.createElement('label');
                            label.className = 'text-success';
                            label.textContent = 'Await Confirmation';
                            card.querySelector('.status-container').appendChild(label);
                        }
                        else if (actionValue === 'track') {
                            // Show the map on the rider's dashboard
                            document.getElementById('rider-location-map').style.display = 'block';
                            
                            // Initialize the map for the current delivery request
                            initRiderMap(pickupAddress, deliveryAddress);
                            
                            socket.emit('join_rider_room', { request_id: requestID });
                            
                            // Start sending rider's real-time location
                            getRiderLocation(requestID); // This function will start tracking and sending location updates
                        }
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => console.error('Error:', error));
            });
        });


        let riderMap, riderRoute, liveMarker;

        function initRiderMap(pickup, delivery) {
        if (riderMap) riderMap.remove();

            riderMap = L.map('rider-map').setView([6.3249, 8.1137], 13);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
                attribution: '&copy; OpenStreetMap contributors'
        }).addTo(riderMap);

        Promise.all([
            geocodeAddress(pickup),
            geocodeAddress(delivery)
        ]).then(([pickupCoords, deliveryCoords]) => {
                    L.marker(pickupCoords).addTo(riderMap).bindPopup("Pickup Location");
                    L.marker(deliveryCoords).addTo(riderMap).bindPopup("Delivery Location");

                    riderRoute = L.Routing.control({
                    waypoints: [L.latLng(pickupCoords), L.latLng(deliveryCoords)],
                    routeWhileDragging: false,
                    addWaypoints: false
                }).addTo(riderMap);

                // Get rider’s live location
                if (navigator.geolocation) {
                    navigator.geolocation.watchPosition(pos => {
                        const lat = pos.coords.latitude;
                        const lng = pos.coords.longitude;

                        const icon = L.icon({
                            iconUrl: 'https://maps.google.com/mapfiles/kml/shapes/motorcycling.png',
                            iconSize: [40, 40]
                        });

                        if (!liveMarker) {
                            liveMarker = L.marker([lat, lng], { icon }).addTo(riderMap)
                            .bindPopup("You are here").openPopup();
                        } else {
                            liveMarker.setLatLng([lat, lng]);
                        }

                        riderMap.panTo([lat, lng]);
                    });
                } else {
                    alert("Geolocation not supported by this browser.");
                }
            });
        }

        // Reuse geocode function from before
        function geocodeAddress(address) {
        const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}`;
        return fetch(url)
            .then(res => res.json())
            .then(data => [parseFloat(data[0].lat), parseFloat(data[0].lon)]);
        }


        // Email truncation
        const emailInput = document.getElementById('rider-email');
        emailInput.textContent = formatEmail(emailInput.textContent);

        function formatEmail(email) {
            const [name, domain] = email.split('@');
            const briefName = name.length > 8 ? name.substring(0, 8) + '...' : name;
            return `${briefName}@${domain}`;
        }

        // function truncateText(text, maxLength) {
        //     return text.length > maxLength ? text.slice(0, maxLength) + "..." : text;
        // }

        // Apply truncation to email label
        // const emailLabel = document.getElementById("rider-mail");
        // const emailText = emailLabel.innerText || emailLabel.textContent;
        // emailLabel.innerText = truncateText(emailText, 8); // Set maxLength as needed

        // Play a notification sound when a new delivery request is received
        function playNotificationSound() {
            let audio = new Audio('https://www.myinstants.com/media/sounds/bell-notification.mp3');
            audio.play();
        }

        // Connect to the WebSocket server
        const socket = io('http://127.0.0.1:5000'); // Update this URL if your server is hosted differently

        // Initialize the notification count
        let notificationCount = parseInt(document.getElementById('notify').innerText);

        // Listen for new delivery request notifications
        socket.on('new_delivery_request', function(data) {
            // Increment the notification count
            notificationCount++;

            // Update the badge with the new count
            document.getElementById('notify').innerText = notificationCount;
            playNotificationSound();

            // Optionally, you could also add some UI effects like blinking or highlighting to grab attention
            document.getElementById('notify').classList.add('badge-highlight');
            
            // Remove the highlight effect after a few seconds
            setTimeout(function() {
                document.getElementById('notify').classList.remove('badge-highlight');
            }, 2000);
        });

        /*const socket = io(); // Connect to the WebSocket server

        // Listen for the "request_confirmed" event
        socket.on('request_confirmed', (data) => {
            const requestId = data.request_id;

            // Remove the confirmed request from the DOM
            const requestElement = document.querySelector(`[data-id="${requestId}"]`);
            if (requestElement) {
                requestElement.closest('.col-lg-4').remove();
            }
        });*/

        function initMap(pickupAddress, deliveryAddress, requestId) {
            const geocoder = new google.maps.Geocoder();
        
            // Geocode the pickup address to get the coordinates
            geocoder.geocode({ 'address': pickupAddress }, (pickupResults, status1) => {
                if (status1 === 'OK') {
                    // Geocode the delivery address to get the coordinates
                    geocoder.geocode({ 'address': deliveryAddress }, (deliveryResults, status2) => {
                        if (status2 === 'OK') {
                            // Initialize the map centered on the pickup location
                            const map = new google.maps.Map(document.getElementById('rider-map'), {
                                zoom: 15,
                                center: pickupResults[0].geometry.location
                            });
        
                            // Place markers for pickup and delivery locations
                            const pickupMarker = new google.maps.Marker({
                                position: pickupResults[0].geometry.location,
                                map: map,
                                label: "P"
                            });
        
                            const deliveryMarker = new google.maps.Marker({
                                position: deliveryResults[0].geometry.location,
                                map: map,
                                label: "D"
                            });
        
                            // Create the rider's marker (it will be updated with real-time GPS data)
                            const riderMarker = new google.maps.Marker({
                                position: pickupResults[0].geometry.location, // Initialize at pickup location
                                map: map,
                                icon: 'https://maps.google.com/mapfiles/kml/shapes/motorcycling.png'
                            });
        
                            // Start watching the rider's position using the real GPS
                            watchRiderPosition(requestId, riderMarker, map);
                        } else {
                            alert('Error finding delivery address.');
                        }
                    });
                } else {
                    alert('Error finding pickup address.');
                }
            });
        }
        
        // Function to get rider's location and send updates via SocketIO
        function getRiderLocation(requestId) {
            if (navigator.geolocation) {
                navigator.geolocation.watchPosition(function(position) {
                    const lat = position.coords.latitude;
                    const lng = position.coords.longitude;
        
                    // Send the coordinates to the server via SocketIO
                    socket.emit('update_rider_location', {
                        request_id: requestId,
                        lat: lat,
                        lng: lng
                    });
                }, function(error) {
                    console.error('Geolocation error: ', error);
                }, {
                    enableHighAccuracy: true,
                    timeout: 5000,
                    maximumAge: 0
                });
            } else {
                alert('Geolocation is not supported by your browser.');
            }
        }
    });
}

if (window.location.pathname.includes('rider_settings')) {
    document.addEventListener('DOMContentLoaded', () => {
        // Update the greeting message and time display
        function updateTime() {
            var now = new Date(); // Get current time
            var current_time = now.toLocaleTimeString(); // Format time as HH:MM:SS
            var time_display = document.getElementById('time-display');
            time_display.innerHTML = current_time; // Update the HTML element

            let time_greeting = now;
            let hours = time_greeting.getHours();

            if (hours >= 17) {  // 5:00 PM and later
                document.getElementById('greeting').innerHTML = 'Good Evening';
            } else if (hours >= 12) {  // 12:00 PM to 4:59 PM
                document.getElementById('greeting').innerHTML = 'Good Afternoon';
            } else {  // Before 12:00 PM
                document.getElementById('greeting').innerHTML = 'Good Morning';
            }
        }

        // Call the updateTime function every second (1000 ms)
        setInterval(updateTime, 1000);

        // Run the updateTime function on page load to ensure it's immediately shown
        updateTime()

        // Enable/Disable input fields
        const enableButton = document.getElementById("enable-input");
        if (!enableButton) return; // Ensure the button exists before proceeding

        enableButton.addEventListener('click', (event) => {
            const rider_name = document.getElementById("rider_name");
            const rider_email = document.getElementById("rider_email");
            const rider_password = document.getElementById("rider_password");
            const rider_number = document.getElementById("rider_number");
            const submitButton = document.getElementById('btn-submitpofile');
            const button = event.target; // Reference to the button itself

            if (rider_name.disabled) {
                // Enable the input fields
                rider_name.disabled = false;
                rider_email.disabled = false;
                rider_password.disabled = false;
                rider_number.disabled = false;
                submitButton.disabled = false;
                button.textContent = 'Disable'; // Change button text to "Disable"
            } else {
                // Disable the input fields
                rider_name.disabled = true;
                rider_email.disabled = true;
                rider_password.disabled = true;
                rider_number.disabled = true;
                submitButton.disabled = true;
                button.textContent = 'Enable'; // Change button text to "Enable"
            }
        });

        // 
        const enableBtnVehicle = document.getElementById("enable-input-vehiclesettings");
        if (!enableBtnVehicle) return; // Ensure the button exists before proceeding

        enableBtnVehicle.addEventListener('click', (event) => {
            const rider_vehicle = document.getElementById("rider_vehicle");
            const rider_plate = document.getElementById("rider_plate");
            const rider_location = document.getElementById("rider_location");
            const rider_status = document.getElementById("rider_status");
            const submitButton2 = document.getElementById('btn-submitvehiclesettings');
            const button2 = event.target; // Reference to the button itself

            if (rider_vehicle.disabled) {
                // Enable the input fields
                rider_vehicle.disabled = false;
                rider_plate.disabled = false;
                rider_location.disabled = false;
                rider_status.disabled = false;
                submitButton2.disabled = false;
                button2.textContent = 'Disable'; // Change button text to "Disable"
            } else {
                // Disable the input fields
                rider_vehicle.disabled = true;
                rider_plate.disabled = true;
                rider_location.disabled = true;
                rider_status.disabled = true;
                submitButton2.disabled = true;
                button2.textContent = 'Enable'; // Change button text to "Enable"
            }
        });

        // Email truncation
        const emailInput = document.getElementById('rider-email');
        emailInput.textContent = formatEmail(emailInput.textContent);

        function formatEmail(email) {
            const [name, domain] = email.split('@');
            const briefName = name.length > 8 ? name.substring(0, 8) + '...' : name;
            return `${briefName}@${domain}`;
        }
    });
}