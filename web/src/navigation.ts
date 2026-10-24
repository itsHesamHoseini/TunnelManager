export const destinations = ['overview', 'tunnels', 'servers', 'events', 'certificates', 'settings'] as const;
export const groups: Record<string, string[]> = {
 overview: ['overview'], tunnels: ['tunnels', 'routes', 'discovery'],
 servers: ['servers', 'services', 'ports', 'tags', 'monitoring'],
 events: ['operations', 'alerts'], certificates: ['certificates'], settings: ['settings', 'security'],
};
export const areaOf = (page: string) => Object.keys(groups).find(area => groups[area].includes(page)) || 'overview';
export type LocationState = {page: string; node?: {id: string; tab: string; instance: string}; workspace?: {selected?: string; tab?: string; create?: boolean}};
export function locationHash(state: LocationState) {
 const area = areaOf(state.page), params = new URLSearchParams();
 if(state.page !== groups[area][0]) params.set('view', state.page);
 if(state.node){params.set('node', state.node.id);params.set('tab', state.node.tab);if(state.node.instance)params.set('instance',state.node.instance)}
 if(state.workspace?.selected){params.set('tunnel',state.workspace.selected);params.set('tab',state.workspace.tab || 'status')}
 if(state.workspace?.create) params.set('create','1');
 return '#/'+area+(params.size?'?'+params.toString():'');
}
export function readLocation(hash: string): LocationState {
 const [path, query=''] = hash.replace(/^#\/?/,'').split('?'), params = new URLSearchParams(query);
 const area = groups[path] ? path : areaOf(path);
 const requested = params.get('view') || path;
 const page = groups[area].includes(requested) ? requested : groups[area][0];
 const state: LocationState = {page};
 if(area==='servers' && params.get('node'))state.node={id:params.get('node')!,tab:params.get('tab')||'overview',instance:params.get('instance')||''};
 if(area==='tunnels' && params.get('tunnel'))state.workspace={selected:params.get('tunnel')!,tab:params.get('tab')||'status'};
 else if(area==='tunnels' && params.get('create')==='1')state.workspace={create:true};
 return state;
}
