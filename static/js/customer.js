if (window.location.pathname.includes('dashboard')) {
    document.addEventListener('DOMContentLoaded', function () {
        // Form Elements
        let deliveryrequestForm = document.getElementById('delivery-request-form');
        let waybillForm = document.getElementById('waybill-form');
        let handoffForm = document.getElementById('handoff-form');
        let foodForm = document.getElementById('food-form');
        let delivery_type = document.getElementById('delivery_type');

        // Form Buttons
        let requestBtn = document.getElementById('request-buttons');
        let waybillBtn = document.getElementById('waybill-button');
        let handoffBtn = document.getElementById('handoff-button');
        let foodBtn = document.getElementById('food-button');
        let waybillBtn_2 = document.getElementById('waybill-button-2');
        let handoffBtn_2 = document.getElementById('handoff-button-2');
        let foodBtn_2 = document.getElementById('food-button-2');

        // When the page loads, this function will be executed
        window.onload = function() {
            orders.classList.remove('hidden'); // Change the display property to show the element
            if (orders){
                requestBtn.classList.add('hidden');
            }
        };

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

        // Event listeners for the delivery type buttons (waybill, handoff, food) when orders containers is not visible
        waybillBtn.addEventListener('click', () => {
            deliveryrequestForm.style.display = 'block';
            waybillForm.style.display = 'block';
            handoffForm.style.display = 'none';
            foodForm.style.display = 'none';
            requestBtn.classList.add('hidden');
            delivery_type.value = "waybill";
        });
        handoffBtn.addEventListener('click', () => {
            deliveryrequestForm.style.display = 'block';
            handoffForm.style.display = 'block';
            waybillForm.style.display = 'none';
            foodForm.style.display = 'none';
            requestBtn.classList.add('hidden');
            delivery_type.value = "handoff";
        });
        foodBtn.addEventListener('click', () => {
            deliveryrequestForm.style.display = 'block';
            foodForm.style.display = 'block';
            waybillForm.style.display = 'none';
            handoffForm.style.display = 'none';
            requestBtn.classList.add('hidden');
            delivery_type.value = "food";
        });

        // when orders container is visible for the delivery type buttons (waybill, handoff, food)
        if (waybillBtn_2) {
            waybillBtn_2.addEventListener('click', () => {
                deliveryrequestForm.style.display = 'block';
                waybillForm.style.display = 'block';
                handoffForm.style.display = 'none';
                foodForm.style.display = 'none';
                requestBtn.classList.add('hidden');
                orders.classList.add('hidden');
                delivery_type.value = "waybill";
            });
        }
        if (handoffBtn_2) {
            handoffBtn_2.addEventListener('click', () => {
                deliveryrequestForm.style.display = 'block';
                handoffForm.style.display = 'block';
                waybillForm.style.display = 'none';
                foodForm.style.display = 'none';
                requestBtn.classList.add('hidden');
                orders.classList.add('hidden');
                delivery_type.value = "handoff";
            });
        }
        if (foodBtn_2) {
            foodBtn_2.addEventListener('click', () => {
                deliveryrequestForm.style.display = 'block';
                foodForm.style.display = 'block';
                waybillForm.style.display = 'none';
                handoffForm.style.display = 'none';
                requestBtn.classList.add('hidden');
                orders.classList.add('hidden');
                delivery_type.value = "food";
            });
        }

        // Update required fields
        function updateRequiredFields() {
            const waybillFormFields = waybillForm.querySelectorAll("[required]");
            const handoffFormFields = handoffForm.querySelectorAll("[required]");
            const foodFormFields = foodForm.querySelectorAll("[required]");
        
            if (waybillForm.style.display === "block") {
                waybillFormFields.forEach(field => field.setAttribute("required", ""));
                handoffFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
                foodFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
            } else if (handoffForm.style.display === "block") {
                handoffFormFields.forEach(field => field.setAttribute("required", ""));
                waybillFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
                foodFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
            } else if (foodForm.style.display === "block") {
                foodFormFields.forEach(field => field.setAttribute("required", ""));
                waybillFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
                handoffFormFields.forEach(field => {
                    field.removeAttribute("required");
                    field.value = ""; // Clear hidden field values
                });
            }
        }

        // Transport fee calculation (unchanged)
        function calculateTransportFee(packageWorth) {
            if (packageWorth <= 10000) {
                return Math.floor(0.10 * packageWorth) + 4500;
            } else if (packageWorth <= 50000) {
                return Math.floor(0.07 * packageWorth) + 4500;
            } else if (packageWorth <= 100000) {
                return Math.floor(0.05 * packageWorth) + 4500;
            } else if (packageWorth <= 500000) {
                return Math.floor(0.03 * packageWorth) + 4500;
            } else {
                return Math.floor(0.02 * packageWorth) + 4500;
            }
        }
        // for waybill type
        document.getElementById('waybillpackworth').addEventListener('input', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const packageWorth = parseFloat(sanitizedValue) || 0;
            const transportFee = calculateTransportFee(packageWorth);
            document.getElementById('transport_fee').textContent = transportFee.toLocaleString();
        });

        document.getElementById('waybillpackworth').addEventListener('blur', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const formattedValue = parseFloat(sanitizedValue).toLocaleString();
            this.value = formattedValue || '';
        });
        // for handoff type
        document.getElementById('handoffpackworth').addEventListener('input', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const packageWorth = parseFloat(sanitizedValue) || 0;
            const transportFee = calculateTransportFee(packageWorth);
            document.getElementById('transport_fee').textContent = transportFee.toLocaleString();
        });

        document.getElementById('handoffpackworth').addEventListener('blur', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const formattedValue = parseFloat(sanitizedValue).toLocaleString();
            this.value = formattedValue || '';
        });
        // for food type
        document.getElementById('foodworth').addEventListener('input', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const packageWorth = parseFloat(sanitizedValue) || 0;
            const transportFee = calculateTransportFee(packageWorth);
            document.getElementById('transport_fee').textContent = transportFee.toLocaleString();
        });

        document.getElementById('foodworth').addEventListener('blur', function() {
            const sanitizedValue = this.value.replace(/,/g, '');
            const formattedValue = parseFloat(sanitizedValue).toLocaleString();
            this.value = formattedValue || '';
        });

        // Submit requests base on types (waybill, handoff, food)
        document.getElementById('submit-request').addEventListener('click', async (event) => {
            event.preventDefault();
            updateRequiredFields();
        
            // const delivery_type = document.getElementById('delivery_type');
        
            /* if (waybillForm.style.display === "block") {
                delivery_type.value = "waybill";
            } else if (handoffForm.style.display === "block") {
                delivery_type.value = "handoff";
            } else if (foodForm.style.display === "block") {
                delivery_type.value = "food";
            } */
        
            if (deliveryrequestForm.checkValidity()) {
                try {
                    const formData = new FormData(deliveryrequestForm);
        
                    const response = await fetch("/request_delivery", {
                        method: "POST",
                        body: formData,
                    });
        
                    const data = await response.json();
        
                    if (response.ok) {
                        // Update summary fields
                        document.getElementById("type").textContent = data.delivery_type;
                        document.getElementById("request-id").textContent = data.request_id;
        
                        if (delivery_type.value === 'waybill') {
                            document.getElementById("pickup-summary").textContent = data.waybillpickupaddress;
                            document.getElementById("delivery-summary").textContent = data.waybilldeliveryaddress;
                            document.getElementById("package-summary").textContent = data.waybillpackDesc;
                            document.getElementById("worth-summary").textContent = data.waybillpackworth;
                            document.getElementById("pickupNumber-summary").textContent = data.waybillpickupnumber;
                            document.getElementById("busNumber-summary").textContent = data.waybillbusno;
                            document.getElementById("state-summary").textContent = data.waybilldeliverystate;
                            document.getElementById("pickupNumber-summary-container").classList.remove('hidden');
                            document.getElementById("busNumber-summary-container").classList.remove('hidden');
                        } else if (delivery_type.value === 'handoff') {
                            document.getElementById("recipientName-summary").textContent = data.handoffrecipientname;
                            document.getElementById("recipientNumber-summary").textContent = data.handoffrecipientnumber;
                            document.getElementById("pickup-summary").textContent = data.handoffpickupaddress;
                            document.getElementById("delivery-summary").textContent = data.handoffrecipientaddress;
                            document.getElementById("package-summary").textContent = data.handoffpackageItem;
                            document.getElementById("worth-summary").textContent = data.handoffpackworth;
                            document.getElementById("state-summary").textContent = data.handoffdeliverystate;
                            document.getElementById("recipient-summary").classList.remove('hidden');
                        } else if (delivery_type.value === 'food') {
                            document.getElementById("restaurantName-summary").textContent = data.restaurantname;
                            document.getElementById("recipientName-summary").textContent = data.restaurantrecptname;
                            document.getElementById("recipientNumber-summary").textContent = data.restaurantrecptnumber;
                            document.getElementById("pickup-summary").textContent = data.restaurantaddress;
                            document.getElementById("delivery-summary").textContent = data.fooddeliveryaddress;
                            document.getElementById("package-summary").textContent = data.foodItem;
                            document.getElementById("worth-summary").textContent = data.foodworth;
                            document.getElementById("state-summary").textContent = data.fooddeliverystate;
                            document.getElementById("restaurant-summary").classList.remove('hidden');
                            document.getElementById("recipient-summary").classList.remove('hidden');
                        }
        
                        // Show summary section and hide form section
                        document.getElementById('delivery-request-form').style.display = 'none';
                        document.getElementById('summary').classList.remove('hidden');
                    } else {
                        alert(`Error: ${data.error}`);
                    }
                } catch (error) {
                    console.error("Error details:", error);
                    alert("There was an error with the request. Please try again.");
                }
            } else {
                deliveryrequestForm.reportValidity();
            }
        });

        // Payment handling
        document.getElementById('payment').addEventListener('click', (event) => {
            // Prevent multiple clicks
            event.preventDefault();
            const btn_payment = event.target;
            btn_payment.disabled = true;
            
            const delivery_type = document.getElementById('delivery_type').value;
        
            const requestData = {
                // Common data
                request_id: document.getElementById('request-id').textContent,
                customer_id: document.getElementById('c-id').textContent,
                customer_name: document.getElementById('c-name').textContent,
                customer_mail: document.getElementById('c-mail').textContent,
                customer_number: document.getElementById('c-number').textContent,
                pickup_location: document.getElementById('pickup-summary').textContent,
                delivery_address: document.getElementById('delivery-summary').textContent,
                package_description: document.getElementById('package-summary').textContent,
                package_worth: document.getElementById('worth-summary').textContent,
                state: document.getElementById('state-summary').textContent,
                transaction_date: document.getElementById('date').textContent,
                transaction_time: document.getElementById('time-display').textContent,
                transport_fee: document.getElementById('transport_fee').textContent,
                delivery_type: delivery_type
            };
        
            // Add delivery-type-specific data
            if (delivery_type === 'waybill') {
                requestData.pickup_number = document.getElementById('pickupNumber-summary').textContent;
                requestData.bus_number = document.getElementById('busNumber-summary').textContent;
            } else if (delivery_type === 'handoff') {
                requestData.recipient_name = document.getElementById('recipientName-summary').textContent;
                requestData.recipient_number = document.getElementById('recipientNumber-summary').textContent;
            } else if (delivery_type === 'food') {
                requestData.restaurant_name = document.getElementById('restaurantName-summary').textContent;
                requestData.recipient_name = document.getElementById('recipientName-summary').textContent;
                requestData.recipient_number = document.getElementById('recipientNumber-summary').textContent;
            }
        
            // Send data to server for payment processing
            fetch('/request_payment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestData),
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.payment_url) {
                        window.location.href = data.payment_url;
                    } else {
                        console.error('Payment initialization failed:', data.message);
                    }
                })
                .catch((error) => {
                    console.error('Error:', error);
                    btn_payment.disabled = false;
                });
        });

        // Confirming deliveries
        document.querySelectorAll('button[name="action"]').forEach(button => {
            button.addEventListener('click', function (event) {
                event.preventDefault(); // Prevent the default form submission

                const requestID = this.closest('.card').querySelector('input[name="reqID"]').value;
                const actionValue = this.value;
                const riderName = this.getAttribute('data-rider');

                // Prepare data to send
                const requestData = {
                    reqID: requestID,
                    action: actionValue
                };

                // Send the data using fetch API
                fetch('/dashboard', {
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
                        if (actionValue === 'confirm') {
                            // Update the page dynamically based on response
                            alert(data.message);
                            // location.reload();
                            this.closest('.col-lg-6').remove();
                            document.getElementById('ratingRequestId').value = requestID;
                            document.getElementById('ratingRiderName').value = riderName;
                            new bootstrap.Modal(document.getElementById('ratingModal')).show();
                            // Optionally, you can remove the confirmed request from the DOM, update status, etc. 
                        } else if (actionValue === 'track') {
                            const pickup = this.getAttribute('data-pickup');
                            const delivery = this.getAttribute('data-delivery');
                            // Show map container
                            document.getElementById('rider-location-map').style.display = 'block';

                            // Initialize map
                            initLeafletMap(pickup, delivery);

                            // alert(data.message);
                        }
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => console.error('Error:', error));
            });
        });

        let map, pickupMarker, deliveryMarker, riderMarker, routeControl;

        function initLeafletMap(pickupAddress, deliveryAddress) {
        if (map) {
            map.remove();
        }

        map = L.map('rider-map').setView([6.3249, 8.1137], 13); // Default Abakaliki center

        // Add base map
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);

        // Use Nominatim to geocode addresses
        Promise.all([
            geocodeAddress(pickupAddress),
            geocodeAddress(deliveryAddress)
        ]).then(([pickupCoords, deliveryCoords]) => {
                // Add pickup and delivery markers
                pickupMarker = L.marker(pickupCoords).addTo(map)
                .bindPopup('<b>Pickup Location</b>').openPopup();

                deliveryMarker = L.marker(deliveryCoords).addTo(map)
                .bindPopup('<b>Delivery Location</b>');

                // Draw route
                routeControl = L.Routing.control({
                waypoints: [L.latLng(pickupCoords), L.latLng(deliveryCoords)],
                routeWhileDragging: false,
                addWaypoints: false
                }).addTo(map);

                // Simulate rider moving along route
                simulateRider(pickupCoords, deliveryCoords);

                // Calculate distance and fare
                calculateDistanceAndFare(pickupCoords, deliveryCoords);
            });
        }

        // Geocode with Nominatim (OpenStreetMap)
        function geocodeAddress(address) {
            const url = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}`;
            return fetch(url)
            .then(res => res.json())
            .then(data => {
                if (data && data[0]) {
                    return [parseFloat(data[0].lat), parseFloat(data[0].lon)];
                } else {
                    alert("Address not found: " + address);
                    return [6.3249, 8.1137]; // fallback to Abakaliki
                }
            });
        }

        // Simulate moving rider
        function simulateRider(start, end) {
            const latDiff = (end[0] - start[0]) / 100;
            const lngDiff = (end[1] - start[1]) / 100;
            let step = 0;

            const bikeIcon = L.icon({
                iconUrl: 'https://cdn-icons-png.flaticon.com/512/854/854894.png',
                iconSize: [40, 40]
            });

            riderMarker = L.marker(start, { icon: bikeIcon }).addTo(map)
                .bindPopup('<b>Rider Moving...</b>');

            const interval = setInterval(() => {
                if (step >= 100) {
                    clearInterval(interval);
                    riderMarker.bindPopup('<b>Rider Arrived!</b>').openPopup();
                    return;
                }

                const newLat = start[0] + (latDiff * step);
                const newLng = start[1] + (lngDiff * step);
                riderMarker.setLatLng([newLat, newLng]);
                map.panTo([newLat, newLng]);
                step++;
            }, 1000);
        }

        // Distance + Fare
        function calculateDistanceAndFare(start, end) {
            const R = 6371; // km
            const dLat = (end[0] - start[0]) * Math.PI / 180;
            const dLon = (end[1] - start[1]) * Math.PI / 180;
            const a = Math.sin(dLat/2) ** 2 + Math.cos(start[0]*Math.PI/180) * Math.cos(end[0]*Math.PI/180) * Math.sin(dLon/2) ** 2;
            const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
            const distanceKm = R * c;

            const fare = Math.max(500, distanceKm * 150);
            console.log(`Distance: ${distanceKm.toFixed(2)} km`);
            console.log(`Estimated Fare: ₦${fare.toFixed(0)}`);
        }


        // Email truncation
        const emailInput = document.getElementById('mail');
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
        // const emailLabel = document.getElementById("mail");
        // const emailText = emailLabel.innerText || emailLabel.textContent;
        // emailLabel.innerText = truncateText(emailText, 8); // Set maxLength as needed

        // Apply truncation to Name label
        // const nameLabel = document.getElementById("c-name");
        // const nameText = nameLabel.innerText || nameLabel.textContent;
        // nameLabel.innerText = truncateText(nameText, 15);

        // Rating stars
        document.querySelectorAll('.star').forEach(star => {
            star.addEventListener('click', function () {
                const value = this.getAttribute('data-value'); // Get the selected star value
                document.getElementById('ratingInput').value = value; // Set the value in the hidden input
        
                // Fill stars up to the selected one
                document.querySelectorAll('.star').forEach(s => {
                    s.classList.remove('filled'); // Clear all filled stars
                    if (s.getAttribute('data-value') <= value) {
                        s.classList.add('filled'); // Fill stars up to the selected one
                    }
                });
            });
        
            star.addEventListener('mouseover', function () {
                const value = this.getAttribute('data-value');
                document.querySelectorAll('.star').forEach(s => {
                    s.classList.remove('filled'); // Reset all stars
                    if (s.getAttribute('data-value') <= value) {
                        s.classList.add('filled'); // Temporarily fill stars up to the hovered one
                    }
                });
            });
        
            star.addEventListener('mouseout', function () {
                const value = document.getElementById('ratingInput').value; // Get the currently selected value
                document.querySelectorAll('.star').forEach(s => {
                    s.classList.remove('filled'); // Clear all stars
                    if (s.getAttribute('data-value') <= value) {
                        s.classList.add('filled'); // Reapply filled stars up to the selected value
                    }
                });
            });
        });

        // Submit rating
        document.getElementById('submitRatingBtn').addEventListener('click', function () {
            const formData = new FormData(document.getElementById('ratingForm'));
            fetch('/submit-rating', {
                method: 'POST',
                body: JSON.stringify(Object.fromEntries(formData)),
                headers: { 'Content-Type': 'application/json' }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    // Close the modal
                    bootstrap.Modal.getInstance(document.getElementById('ratingModal')).hide();
                } else {
                    alert(data.message);
                }
            });
        });
    });
}

if (window.location.pathname.includes('customer_settings')) {
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
        document.getElementById("enable-input").addEventListener('click', (event) => {
            const customer_name = document.getElementById("customer_name");
            const customer_email = document.getElementById("customer_email");
            const customer_password = document.getElementById("customer_password");
            const customer_number = document.getElementById("customer_number");
            const btn_submitpofile = document.getElementById("btn-submitpofile");
            const button = event.target; // Use event.target to reference the button
        
            if (customer_name.disabled) {
                // Enable the input fields
                customer_name.disabled = false;
                customer_email.disabled = false;
                customer_password.disabled = false;
                customer_number.disabled = false;
                btn_submitpofile.disabled = false;
                button.textContent = 'Disable'; // Change button text to "Disable"
            } else {
                // Disable the input fields
                customer_name.disabled = true;
                customer_email.disabled = true;
                customer_password.disabled = true;
                customer_number.disabled = true;
                btn_submitpofile.disabled = true;
                button.textContent = 'Enable'; // Change button text to "Enable"
            }
        });

        // Email truncation
        const emailInput = document.getElementById('mail');
        emailInput.textContent = formatEmail(emailInput.textContent);

        function formatEmail(email) {
            const [name, domain] = email.split('@');
            const briefName = name.length > 8 ? name.substring(0, 8) + '...' : name;
            return `${briefName}@${domain}`;
        }
    });
}

if (window.location.pathname.includes('customer_history')) {
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

        // Email truncation
        const emailInput = document.getElementById('mail');
        emailInput.textContent = formatEmail(emailInput.textContent);

        function formatEmail(email) {
            const [name, domain] = email.split('@');
            const briefName = name.length > 8 ? name.substring(0, 8) + '...' : name;
            return `${briefName}@${domain}`;
        }
    });
}
