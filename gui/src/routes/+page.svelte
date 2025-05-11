<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { invoke } from '@tauri-apps/api/tauri';

    let interfaces: string = '';
    let intervalId: ReturnType<typeof setInterval>;

    async function updateInterfaces() {
        try {
            interfaces = await invoke('get_interfaces');
        } catch (error) {
            console.error('Failed to fetch interfaces:', error);
        }
    }

    onMount(() => {
        updateInterfaces();
        // Обновление каждую минуту
        intervalId = setInterval(updateInterfaces, 60000);
    });

    onDestroy(() => {
        if (intervalId) {
            clearInterval(intervalId);
        }
    });
</script>

<div class="welcome-text">
    <div class="interfaces-list">
        <pre>{interfaces}</pre>
    </div>
</div>

<style>
    .welcome-text {
        font-family: 'Jolly Lodger', monospace;
        font-size: 16px;
        color: #40C057;
    }

    .interfaces-list {
        margin-top: 20px;
    }

    .interfaces-list pre {
        font-family: 'JetBrains Mono', monospace;
        font-size: 16px;
        color: #40C057;
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    h1, h2 {
        font-family: 'JetBrains Mono', monospace;
        color: #40C057;
    }
</style>
