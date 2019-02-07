import { IHttpOperation } from '@stoplight/types';
import { IFilesystemLoaderOpts } from '../../types';
import { GraphFacade } from '../../utils/graphFacade';

const DEFAULT_PATH = '.';

export class FilesystemLoader {
  constructor(private graphFacade: GraphFacade) {}

  /**
   * TODO(sl-732): we can't assure we will return an array of 'Resource'.
   * There is no way to filter by a type in runtime :(
   */
  public async load(/*<Resource>*/ _opts?: IFilesystemLoaderOpts): Promise<IHttpOperation[]> {
    const fsPath = _opts ? _opts.path : DEFAULT_PATH;
    await this.graphFacade.createFilesystemNode(fsPath);
    return this.graphFacade.httpOperations;
  }
}

export const filesystemLoaderInstance = new FilesystemLoader(new GraphFacade());