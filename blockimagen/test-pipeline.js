fetch('http://localhost:3001/api/kling/generate', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'x-api-version': 'TEST'
    },
    body: JSON.stringify({
        type: 'image2video',
        image: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
        model_name: 'kling-v2-6',
        prompt: 'A tiny cute robot dancing in the rain',
        aspect_ratio: '16:9'
    })
})
    .then(res => res.json())
    .then(data => {
        console.log('Generate Response:', data);
        if (data.data && data.data.task_id) {
            const taskId = data.data.task_id;
            console.log('Polling task:', taskId);
            return new Promise(resolve => setTimeout(resolve, 5000)).then(() => {
                return fetch(`http://localhost:3001/api/kling/task/${taskId}?type=image2video&model_name=kling-v2-6`, {
                    headers: { 'x-api-version': 'TEST' }
                })
                    .then(res => res.json())
                    .then(pollData => console.log('Poll Response:', pollData));
            });
        }
    })
    .catch(err => console.error(err));
