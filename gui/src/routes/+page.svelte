<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { invoke } from '@tauri-apps/api/tauri';

    let interfaces: string = '';
    let intervalId: ReturnType<typeof setInterval>;

    async function updateInterfaces() {
        try {
            interfaces = await invoke('get_interfaces') ?? '';
        } catch (error) {
            console.error('Failed to fetch interfaces:', error);
            interfaces = '';
        }
    }

    onMount(() => {
        updateInterfaces();
        intervalId = setInterval(updateInterfaces, 60000);
        return () => {
            if (intervalId) clearInterval(intervalId);
        };
    });
</script>

<div class="welcome-text">
    <!-- Добавьте ваш текст приветствия здесь -->
</div>

{#if interfaces}
    <div class="interfaces-list">
        <ul>
            {#each interfaces.split(',').filter(Boolean) as interfaceName, index (index)}
                <li>
                    <button on:click={() => console.log('Selected:', interfaceName.trim())}>
                        {interfaceName.trim()}
                    </button>
                </li>
            {/each}
        </ul>
    </div>
{:else}
    <div class="no-interfaces">
        No network interfaces found
    </div>
{/if}

<style>
    .welcome-text {
        font-family: 'Jolly Lodger', monospace;
        font-size: 16px;
        color: #40C057;
    }

    .interfaces-list ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }

    .interfaces-list li {
        margin: 8px 0;
    }

    .interfaces-list button {
        font-family: 'JetBrains Mono', monospace;
        font-size: 14px;
        color: #40C057;
        background: transparent;
        border: 1px solid #40C057;
        border-radius: 4px;
        padding: 8px 16px;
        cursor: pointer;
        width: 100%;
        text-align: left;
        transition: all 0.3s ease;
    }

    .interfaces-list button:hover {
        background-color: #40C05722;
    }

    .no-interfaces {
        font-family: 'JetBrains Mono', monospace;
        font-size: 14px;
        color: #FF6B6B;
        margin-top: 20px;
    }
</style>